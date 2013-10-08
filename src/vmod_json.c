#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include <stdio.h>

#include <jansson.h>
#include <glib.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

// TODO: Figure out how to do logging properly here
#define dbgprintf(...)

typedef struct {
	json_t *json;
	enum {
		JSON_STATE_UNSPEC,
		JSON_STATE_GLOBAL,
		JSON_STATE_LOCAL
	} type;
} JsonState;

typedef struct {
	JsonState parent;
	GRecMutex lock;
	GHashTable *locals;
	GHashTable *locals_keys_by_session;
	uint64_t magic;
#define JSON_MAGIC 0xa782945645a92452LL
} JsonGlobalState;

typedef struct {
	JsonState parent;
	GError *error;
	int sess_id;
	bool global : 1;
} JsonLocalState;

// -- prototypes

static gint64 *sess_to_locals_key( struct sess * );
static void locals_key_free( gint64 * );

static JsonLocalState *get_local_state( struct sess *, struct vmod_priv * );

// -- error support

#define VMOD_JSON_ERROR vmod_json_error_quark()

typedef enum {
	VMOD_JSON_ERR_NO_CLOSING_BRACKET,
	VMOD_JSON_ERR_INTERIOR_ARRAY_PREPEND_APPEND,
	VMOD_JSON_ERR_NUMBER_CONVERSION,
	VMOD_JSON_ERR_INVALID_CHARACTERS,
	VMOD_JSON_ERR_OUT_OF_BOUNDS,
	VMOD_JSON_ERR_NOT_FOUND
} VmodJsonErrorCode;

static GQuark vmod_json_error_quark() {
	return g_quark_from_static_string("vmod-json-error-quark");
}

static char *vmod_strerror_r( int errnum, char *buf, size_t buflen ) {
	int saved_errno = errno;
	errno = 0;
	if( strerror_r(errnum, buf, buflen) == -1 ) {
		const char *msg = "Error calling strerror_r";
		memcpy(buf, msg, MIN(strlen(msg), buflen));
		buf[buflen - 1] = '\0';
	}
	errno = saved_errno;
	return buf;
}

static void vmod_json_set_gerror( struct sess *sp, struct vmod_priv *global, GError *error ) {
	g_assert(error != NULL);
	g_propagate_error(&get_local_state(sp, global)->error, error);
}

// init & free functions

static void free_json_local( JsonLocalState *jls ) {
	if( jls->error != NULL ) g_error_free(jls->error);
#ifndef NDEBUG
	memset(jls, 0, sizeof(*jls));
#endif
	g_slice_free(JsonLocalState, jls);
}

static void free_json_global( JsonGlobalState *jgs ) {
	g_assert(jgs->magic == JSON_MAGIC);
	g_hash_table_unref(jgs->locals_keys_by_session);
	g_hash_table_unref(jgs->locals);
	g_rec_mutex_clear(&jgs->lock);
#ifndef NDEBUG
	memset(jgs, 0, sizeof(*jgs));
#endif
	g_slice_free(JsonGlobalState, jgs);
}

static void free_json_state( JsonState *js ) {
	if( js->json != NULL ) json_decref(js->json);

	switch( js->type ) {
		case JSON_STATE_GLOBAL:
			free_json_global((JsonGlobalState *) js);
			break;
		case JSON_STATE_LOCAL:
			free_json_local((JsonLocalState *) js);
			break;
		default:
			g_assert_not_reached();
	}

}

static void init_json_state( JsonState *js ) {
	dbgprintf("init_json_state\n");
	g_assert(js != NULL);
	js->json = json_object();
	g_assert(js->json != NULL);
	js->type = JSON_STATE_UNSPEC;
}

static void init_json_local_state( JsonLocalState *jls, int sess_id ) {
	dbgprintf("init_json_local_state\n");
	init_json_state((JsonState *) jls);
	((JsonState *) jls)->type = JSON_STATE_LOCAL;
	jls->global = false;
	jls->error = NULL;
	jls->sess_id = sess_id;
}

static void init_json_global_state( JsonGlobalState *jgs ) {
	dbgprintf("init_json_global_state\n");
	init_json_state((JsonState *) jgs);
	((JsonState *) jgs)->type = JSON_STATE_GLOBAL;
	jgs->magic = JSON_MAGIC;
	jgs->locals = g_hash_table_new_full(
		g_int64_hash,
		g_int64_equal,
		(GDestroyNotify) locals_key_free,
		(GDestroyNotify) free_json_state
	);
	jgs->locals_keys_by_session = g_hash_table_new(g_direct_hash, g_direct_equal);
	g_rec_mutex_init(&jgs->lock);
}

static JsonGlobalState *new_json_global_state() {
	JsonGlobalState *jgs = g_slice_new(JsonGlobalState);
	init_json_global_state(jgs);
	return jgs;
}

static JsonLocalState *new_json_local_state( int sess_id ) {
	JsonLocalState *jls = g_slice_new(JsonLocalState);
	init_json_local_state(jls, sess_id);
	return jls;
}

static void init_vmod_priv( struct vmod_priv *p, JsonState *js ) {
	g_assert(p->priv == NULL);
	p->priv = js;
	p->free = (vmod_priv_free_f *) free_json_state;
}

int vmod_json_init( struct vmod_priv *global, const struct VCL_conf *conf ) {
	(void) conf;
	dbgprintf("vmod_json_init\n");
	memset(global, 0, sizeof(*global));
	init_vmod_priv(global, (JsonState *) new_json_global_state());
	return 0;
}

// -- borrow functions

static JsonGlobalState *borrow_global_state( struct vmod_priv *global ) {
	JsonGlobalState *jgs = (JsonGlobalState *) global->priv;
	g_assert(jgs->magic == JSON_MAGIC);
	g_assert(((JsonState *) jgs)->type == JSON_STATE_GLOBAL);

	g_rec_mutex_lock(&jgs->lock);
	return jgs;
}

static void return_global_state( JsonGlobalState *jgs ) {
	g_assert(jgs->magic == JSON_MAGIC);
	g_rec_mutex_unlock(&jgs->lock);
}

// I'm really frustrated at the varnish people for making request local scope so hard.
static JsonLocalState *get_local_state( struct sess *sp, struct vmod_priv *global ) {
	dbgprintf("get_local_state: sp->id = %d, sp->xid = %d, sp->esi_level = %u\n", sp->id, sp->xid, sp->esi_level);

	JsonGlobalState *jgs = borrow_global_state(global);

	gint64 *jls_key = sess_to_locals_key(sp);
	gint64 *jls_old_key = g_hash_table_lookup(jgs->locals_keys_by_session, GINT_TO_POINTER(sp->id));

	dbgprintf("get_local_state: jls_key = %" PRId64 ", jls_old_key = %" PRId64 "\n", *jls_key, jls_old_key == NULL ? 0 : *jls_old_key);
	if( jls_old_key != NULL && *jls_key != *jls_old_key ) {
		dbgprintf("get_local_state: clearing old locals with key %" PRId64 "\n", *jls_old_key);
		bool success;
		success = g_hash_table_remove(jgs->locals_keys_by_session, GINT_TO_POINTER(sp->id));
		g_assert(success);
		success = g_hash_table_remove(jgs->locals, jls_old_key);
		g_assert(success);
		jls_old_key = NULL;
	}

	JsonLocalState *jls = g_hash_table_lookup(jgs->locals, jls_key);

	if( jls == NULL ) {
		jls = new_json_local_state(sp->id);
		g_hash_table_replace(jgs->locals, jls_key, jls);
		g_hash_table_insert(jgs->locals_keys_by_session, GINT_TO_POINTER(sp->id), jls_key);
	} else {
		locals_key_free(jls_key);
	}
	g_assert(jls != NULL);

	return_global_state(jgs);

	return jls;
}

static JsonState *borrow_current_state( struct sess *sp, struct vmod_priv *global ) {
	JsonLocalState *jls = get_local_state(sp, global);
	if( jls->global ) {
		dbgprintf("borrow_current_state: global\n");
		return (JsonState *) borrow_global_state(global);
	} else {
		dbgprintf("borrow_current_state: local\n");
		return (JsonState *) jls;
	}
}

static void return_current_state( JsonState *js ) {
	switch( js->type ) {
		case JSON_STATE_GLOBAL:
			return_global_state((JsonGlobalState *) js);
			break;
		case JSON_STATE_LOCAL:
			break;
		default:
			g_assert_not_reached();
	}
}

// -- key path traversal

typedef enum {
	KEY_PATH_OP_UNSPEC,
	KEY_PATH_OP_OBJECT_ACCESS,
	KEY_PATH_OP_ARRAY_PREPEND,
	KEY_PATH_OP_ARRAY_APPEND,
	KEY_PATH_OP_ARRAY_INDEX
} KeyPathOpType;

typedef enum {
	KEY_PATH_VALUE_UNSPEC,
	KEY_PATH_VALUE_OBJECT,
	KEY_PATH_VALUE_ARRAY,
	KEY_PATH_VALUE_LEAF
} KeyPathValueType;

typedef struct {
	KeyPathOpType type;
	KeyPathValueType value_type;
	union {
		size_t index;
		struct {
			const char *buf;
			size_t buflen;
		} key;
	} value;
} KeyPathOp;

static bool key_path_parse_object_op( const char *key_path, KeyPathOp *out, const char **endptr, GError **error ) {
	g_assert(out != NULL);

	size_t i = 0;
	out->value_type = KEY_PATH_VALUE_UNSPEC;
	while( out->value_type == KEY_PATH_VALUE_UNSPEC ) {
		switch( key_path[i] ) {
			case '[':
				out->value_type = KEY_PATH_VALUE_ARRAY;
				break;
			case '.':
				out->value_type = KEY_PATH_VALUE_OBJECT;
				break;
			case '\0':
				out->value_type = KEY_PATH_VALUE_LEAF;
				break;
			default:
				i++;
		}
	}

	dbgprintf("key_path_parse_object_op: *endptr = '%s', i = %zu, *endptr + i = '%s'\n", *endptr, i, *endptr + i);

	if( i == 0 ) {
		// ERROR: No identifier specified
		(void) error;
		g_assert_not_reached();
		return false;
	}

	out->value.key.buf = key_path;
	out->value.key.buflen = i;
	out->type = KEY_PATH_OP_OBJECT_ACCESS;

	*endptr += i;

	return true;
}

static bool key_path_parse_array_append_or_prepend_op( const char *array_index_buf, size_t array_index_buf_len, KeyPathOp *out, GError **error ) {
	g_assert(out != NULL);

	g_assert(array_index_buf_len != 0);
	if( array_index_buf_len != 1 ) {
		(void) error;
		// ERROR: Invalid array operator
		g_assert_not_reached();
	}

	switch( *array_index_buf ) {
		case '>':
			out->type = KEY_PATH_OP_ARRAY_PREPEND;
			break;
		case '<':
			out->type = KEY_PATH_OP_ARRAY_APPEND;
			break;
		default:
			// ERROR: Invalid array operator
			g_assert_not_reached();
	}

#ifndef NDEBUG
	char array_index_vla[array_index_buf_len + 1];
	memcpy(array_index_vla, array_index_buf, array_index_buf_len);
	array_index_vla[array_index_buf_len] = '\0';
	dbgprintf("key_path_parse_array_append_or_prepend_op: array_index_buf = '%s'\n", array_index_vla);
#endif

	return true;
}

static bool key_path_parse_array_index_op( const char *array_index_buf, size_t array_index_buf_len, KeyPathOp *out, GError **error ) {
	g_assert(out != NULL);

	dbgprintf("key_path_parse_array_index_op: array_index_buf = '%s', array_index_buf_len = %zd\n", array_index_buf, array_index_buf_len);

	// Convert the num string into an intmax
	char *array_index_endptr = NULL;
	errno = 0;
	uintmax_t array_index = strtoumax(array_index_buf, &array_index_endptr, 0);
	if( errno != 0 ) {
		char errbuf[1024];
		g_set_error(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_NUMBER_CONVERSION, "Error converting array index to number: %s", vmod_strerror_r(errno, errbuf, 1024));
		return false;
	}
	g_assert(array_index_endptr != NULL);
	if( array_index_endptr != array_index_buf + array_index_buf_len ) {
		g_set_error(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_INVALID_CHARACTERS, "Invalid characters found in array index: '%s'", array_index_endptr);
		return false;
	}

#ifndef NDEBUG
	char array_index_vla[array_index_buf_len + 1];
	memcpy(array_index_vla, array_index_buf, array_index_buf_len);
	array_index_vla[array_index_buf_len] = '\0';
	dbgprintf("key_path_parse_array_index_op: array_index_buf = '%s', array_index = %jd\n", array_index_vla, array_index);
#endif

	if( array_index > SIZE_MAX ) {
		// ERROR: Array index out of bounds
		g_assert_not_reached();
	}

	out->type = KEY_PATH_OP_ARRAY_INDEX;
	out->value.index = (size_t) array_index;
	return true;
}

static bool key_path_parse_array_op( const char *key_path, KeyPathOp *out, const char **endptr, GError **error ) {
	g_assert(out != NULL);
	g_assert(endptr != NULL);

	dbgprintf("key_path_parse_array_op: key_path = '%s'\n", key_path);

	// Figure out the length of the array index
	size_t array_index_len = 0;
	for( array_index_len = 0; key_path[array_index_len] != ']'; array_index_len++ ) {
		if( key_path[array_index_len] == '\0' ) {
			// ERROR: No closing bracket in array index
			g_assert_not_reached();
		}
	}

	switch( key_path[array_index_len + 1] ) {
		case '[':
			out->value_type = KEY_PATH_VALUE_ARRAY;
			break;
		case '.':
			out->value_type = KEY_PATH_VALUE_OBJECT;
			break;
		case '\0':
			out->value_type = KEY_PATH_VALUE_LEAF;
			break;
		default:
			// ERROR: Value type invalid
			g_assert_not_reached();
	}

	bool success = false;

	switch( *key_path ) {
		case '>':
		case '<':
			success = key_path_parse_array_append_or_prepend_op(key_path, array_index_len, out, error);
			break;
		default:
			success = key_path_parse_array_index_op(key_path, array_index_len, out, error);
	}

	*endptr = key_path + array_index_len + 1;

	return success;
}

static bool key_path_parse_op( const char *key_path, KeyPathOp *out, const char **endptr, GError **error ) {
	dbgprintf("key_path_parse_op: key_path = '%s'\n", key_path);

	switch( *key_path ) {
		case '.':
			*endptr += 1;
			return key_path_parse_object_op(key_path + 1, out, endptr, error);
			break;
		case '[':
			*endptr += 1;
			return key_path_parse_array_op(key_path + 1, out, endptr, error);
			break;
		default:
			// ERROR: No operation specified
			g_assert_not_reached();
	}
}

typedef struct {
	json_t *(*func)( json_t *, KeyPathOp *, void *, GError ** );
	void *payload;
} KeyPathTraverser;

static bool key_path_parse( const char *key_path, json_t *top, KeyPathTraverser *traverser, GError **error ) {
	dbgprintf("key_path_parse: key_path = '%s'\n", key_path);

	const char *ptr = key_path, *endptr = key_path + strlen(key_path);
	json_t *cur = top;
	while( ptr < endptr ) {
		switch( *ptr ) {
			case '.':
			case '[': {
				KeyPathOp op;
				if( !key_path_parse_op(ptr, &op, &ptr, error) ) {
					dbgprintf("key_path_parse: return false;\n");
					return false;
				}
				g_assert(ptr <= endptr);
#ifndef NDEBUG
				dbgprintf("key_path_parse: op = {\n\t.type = %d\n\t.value_type = %d\n", op.type, op.value_type);
				switch( op.type ) {
					case KEY_PATH_OP_OBJECT_ACCESS: {
						char buf[op.value.key.buflen + 1];
						memcpy(buf, op.value.key.buf, op.value.key.buflen);
						buf[op.value.key.buflen] = '\0';
						dbgprintf("\t.value.key.buf = '%s'\n", buf);
						break;
					}
					case KEY_PATH_OP_ARRAY_INDEX:
						dbgprintf("\t.value.index = '%jd'\n", op.value.index);
						break;
					default:
						break;
				}
				dbgprintf("};\n");
#endif
				cur = traverser->func(cur, &op, traverser->payload, error);
				if( cur == NULL ) return false;
				break;
			}
			default:
				dbgprintf("key_path_parse: ptr = %p, endptr = %p\n", ptr, endptr);
				dbgprintf("key_path_parse: *ptr = 0x%02x, ptr = '%s'\n", *ptr, ptr);
				// ERROR: No operation specified
				g_assert_not_reached();
		}
		char *top_str = json_dumps(top, JSON_ENCODE_ANY);
		dbgprintf("key_path_parse: iterate, top = '%s'\n", top_str);
		free(top_str);
	}
	traverser->func(cur, NULL, traverser->payload, error);
	return true;
}

static json_t *key_path_create_or_return_value( KeyPathOp *op, json_t *value, GError **error ) {
	if( value != NULL ) {
		json_incref(value);
		return value;
	}

	json_t *ret = NULL;

	switch( op->value_type ) {
		case KEY_PATH_VALUE_ARRAY:
			dbgprintf("key_path_create_or_return_value: json_array()\n");
			ret = json_array();
			break;
		case KEY_PATH_VALUE_OBJECT:
			dbgprintf("key_path_create_or_return_value: json_object()\n");
			ret = json_object();
			break;
		case KEY_PATH_VALUE_LEAF:
			(void) error;
			// ERROR: Value not found
			g_assert_not_reached();
		default:
			g_assert_not_reached();
	}

	g_assert(ret != NULL);
	return ret;
}

static json_t *key_path_get_and_insert_or_create( json_t *cur, KeyPathOp *op, json_t *value, GError **error ) {
	json_t *ret = NULL;

	switch( op->type ) {
		case KEY_PATH_OP_OBJECT_ACCESS: {
			g_assert(json_is_object(cur));

			// Need to copy the key since it's not null terminated in the op
			char key[op->value.key.buflen + 1];
			memcpy(key, op->value.key.buf, op->value.key.buflen);
			key[op->value.key.buflen] = '\0';

			ret = json_object_get(cur, key);
			if( value != NULL && !json_equal(ret, value) ) ret = NULL;
			if( ret == NULL ) {
				json_t *o = key_path_create_or_return_value(op, value, error);
				if( o == NULL ) {
					// TODO: Handle this error
					g_assert_not_reached();
				}
#ifndef NDEBUG
				char *cur_str = json_dumps(cur, JSON_ENCODE_ANY), *o_str = json_dumps(o, JSON_ENCODE_ANY);
				dbgprintf("key_path_get_and_insert_or_create: json_object_set('%s', '%s', '%s')\n", cur_str, key, o_str);
				free(cur_str), free(o_str);
#endif
				int code = json_object_set(cur, key, o);
				g_assert(code == 0);
				json_decref(o);
				ret = o;
			}

			break;
		}
		case KEY_PATH_OP_ARRAY_INDEX:
			g_assert(json_is_array(cur));

			size_t array_size = json_array_size(cur), array_index = op->value.index;
			if( array_size <= array_index ) {
				for( size_t i = array_size; i <= array_index; i++ ) {
					json_t *nul = json_null();
					g_assert(nul != NULL);
					json_array_append_new(cur, nul);
				}
			}

			ret = json_array_get(cur, op->value.index);
			if(
				(value != NULL && !json_equal(ret, value)) ||
				(json_is_null(ret) && op->value_type != KEY_PATH_VALUE_LEAF)
			) {
				ret = NULL;
			}
			if( ret == NULL ) {
				json_t *o = key_path_create_or_return_value(op, value, error);
				if( o == NULL ) {
					// TODO: Handle this error
					g_assert_not_reached();
				}
#ifndef NDEBUG
				{
					char *cur_str = json_dumps(cur, JSON_ENCODE_ANY), *o_str = json_dumps(o, JSON_ENCODE_ANY);
					dbgprintf("key_path_get_and_insert_or_create: json_array_set('%s', %zd, '%s') -> ", cur_str, op->value.index, o_str);
					free(cur_str), free(o_str);
				}
#endif
				int code = json_array_set(cur, op->value.index, o);
				g_assert(code == 0);
#ifndef NDEBUG
				{
					char *cur_str = json_dumps(cur, JSON_ENCODE_ANY);
					dbgprintf("'%s'\n", cur_str);
					free(cur_str);
				}
#endif
				json_decref(o);
				ret = o;
			}
#ifndef NDEBUG
			char *ret_str = json_dumps(ret, JSON_ENCODE_ANY), *value_str = value == NULL ? "(null)" : json_dumps(value, JSON_ENCODE_ANY);
			dbgprintf("key_path_get_and_insert_or_create: ret = '%s', value = '%s'\n", ret_str, value_str);
			free(ret_str);
			if( value != NULL ) free(value_str);
#endif

			break;
		case KEY_PATH_OP_ARRAY_APPEND: {
			g_assert(json_is_array(cur));

			dbgprintf("key_path_get_and_insert_or_create: json_array_append(cur, value)\n");
			json_t *o = key_path_create_or_return_value(op, value, error);
			if( o == NULL ) {
				// TODO: Handle this error
				g_assert_not_reached();
			}
			int code = json_array_append(cur, o);
			g_assert(code == 0);
			json_decref(o);
			ret = o;
			break;
		}
		case KEY_PATH_OP_ARRAY_PREPEND: {
			g_assert(json_is_array(cur));

			dbgprintf("key_path_get_and_insert_or_create: json_array_insert(cur, 0, value)\n");
			json_t *o = key_path_create_or_return_value(op, value, error);
			if( o == NULL ) {
				// TODO: Handle this error
				g_assert_not_reached();
			}
			int code = json_array_insert(cur, 0, o);
			g_assert(code == 0);
			json_decref(o);
			ret = o;
			break;
		}
		default:
			g_assert_not_reached();
	}

	g_assert(ret != NULL);
	return ret;
}

static json_t *key_path_getter_traverser( json_t *cur, KeyPathOp *op, json_t **out, GError **error ) {
	g_assert(out != NULL);
	g_assert(cur != NULL);

	char *cur_str = json_dumps(cur, JSON_ENCODE_ANY);
	dbgprintf("key_path_getter_traverser: cur = '%s'\n", cur_str);
	free(cur_str);

	if( op == NULL ) {
		*out = cur;
		return *out;
	}

	return key_path_get_and_insert_or_create(cur, op, NULL, error);
}

static json_t *key_path_get( json_t *top, const char *key, GError **error ) {
	json_t *value = NULL;
	KeyPathTraverser traverser = {
		.func = (__typeof__(traverser.func)) key_path_getter_traverser,
		.payload = (void *) &value
	};
	if( !key_path_parse(key, top, &traverser, error) ) {
		dbgprintf("key_path_get: return NULL\n");
		return NULL;
	}
	g_assert(value != NULL);
	json_incref(value);
	return value;
}

static json_t *key_path_setter_traverser( json_t *cur, KeyPathOp *op, json_t *value, GError **error ) {
	g_assert(cur != NULL);

	char *cur_str = json_dumps(cur, JSON_ENCODE_ANY), *value_str = json_dumps(value, JSON_ENCODE_ANY);
	dbgprintf("key_path_setter_traverser: cur = '%s', value = '%s'\n", cur_str, value_str);
	free(cur_str), free(value_str);

	if( op == NULL ) {
		g_assert(json_equal(cur, value));
		return cur;
	}

	json_t *ret = NULL;
	switch( op->value_type ) {
		case KEY_PATH_VALUE_LEAF:
			ret = key_path_get_and_insert_or_create(cur, op, value, error);
			if( ret == NULL ) {
				// TODO: Handle error
				g_assert_not_reached();
			}
			g_assert(json_equal(value, ret));
			break;
		case KEY_PATH_VALUE_OBJECT:
		case KEY_PATH_VALUE_ARRAY:
			ret = key_path_get_and_insert_or_create(cur, op, NULL, error);
			if( ret == NULL ) {
				// TODO: Handle error
				g_assert_not_reached();
			}
			break;
		default:
			g_assert_not_reached();
	}
	g_assert(ret != NULL);
	return ret;
}

static bool key_path_insert( json_t *top, const char *key, json_t *value, GError **error ) {
	KeyPathTraverser traverser = {
		.func = (__typeof__(traverser.func)) key_path_setter_traverser,
		.payload = (void *) value
	};
	return key_path_parse(key, top, &traverser, error);
}

// -- misc util functions

static void locals_key_free( gint64 *ptr ) {
	g_slice_free(gint64, ptr);
}

static gint64 *sess_to_locals_key( struct sess *sp ) {
	G_STATIC_ASSERT(sizeof(sp->xid <= 4) && sizeof(sp->esi_level <= 4));
	gint64 *hsh = g_slice_new(gint64);
	*hsh = (((uint64_t) sp->esi_level) << 32) | sp->xid;
	dbgprintf("sess_to_locals_key: sp->xid = 0x%02x, sp->esi_level = 0x%02x, hsh = 0x%02" PRIx64 "\n", sp->xid, sp->esi_level, *hsh);
	return hsh;
}

// -- actual vmod functions

void vmod_global( struct sess *sp, struct vmod_priv *global ) {
	dbgprintf("vmod_global\n");
	get_local_state(sp, global)->global = true;
}

void vmod_local( struct sess *sp, struct vmod_priv *global ) {
	dbgprintf("vmod_local\n");
	get_local_state(sp, global)->global = false;
}

void vmod_string( struct sess *sp, struct vmod_priv *global, const char *key, const char *value ) {
	GError *error = NULL;

	json_t *json_value = json_string(value);
	g_assert(json_value != NULL); // TODO: Runtime error

	JsonState *js = borrow_current_state(sp, global);
	bool success = key_path_insert(js->json, key, json_value, &error);
	return_current_state(js);

	json_decref(json_value);

	if( !success ) {
		g_assert(error != NULL);
		vmod_json_set_gerror(sp, global, error);
		return;
	}
}

void vmod_integer( struct sess *sp, struct vmod_priv *global, const char *key, int value ) {
	GError *error = NULL;

	json_t *json_value = json_integer(value);
	g_assert(json_value != NULL); // TODO: Runtime error

	JsonState *js = borrow_current_state(sp, global);
	bool success = key_path_insert(js->json, key, json_value, &error);
	return_current_state(js);

	json_decref(json_value);

	if( !success ) {
		g_assert(error != NULL);
		vmod_json_set_gerror(sp, global, error);
		return;
	}

	char *json_value_str = json_dumps(json_value, JSON_ENCODE_ANY);
	dbgprintf("vmod_integer: json_value = '%s', success = %s, error = '%s'\n", json_value_str, success ? "true" : "false", success ? "(null)" : error->message);
	free(json_value_str);

	char *js_json_str = json_dumps(js->json, JSON_ENCODE_ANY);
	dbgprintf("vmod_integer: js->json = '%s'\n", js_json_str);
	free(js_json_str);
}

void vmod_real(struct sess *sp, struct vmod_priv *global, const char *key, double value) {
	GError *error = NULL;

	json_t *json_value = json_real(value);
	g_assert(json_value != NULL); // TODO: Runtime error

	JsonState *js = borrow_current_state(sp, global);
	bool success = key_path_insert(js->json, key, json_value, &error);
	return_current_state(js);

	json_decref(json_value);

	if( !success ) {
		g_assert(error != NULL);
		vmod_json_set_gerror(sp, global, error);
		return;
	}
}

void vmod_bool(struct sess *sp, struct vmod_priv *global, const char *key, unsigned value) {
	GError *error = NULL;

	json_t *json_value = json_boolean(value);
	g_assert(json_value != NULL); // TODO: Runtime error

	JsonState *js = borrow_current_state(sp, global);
	bool success = key_path_insert(js->json, key, json_value, &error);
	return_current_state(js);

	json_decref(json_value);

	if( !success ) {
		g_assert(error != NULL);
		vmod_json_set_gerror(sp, global, error);
		return;
	}
}

void vmod_null(struct sess *sp, struct vmod_priv *global, const char *key) {
	GError *error = NULL;

	json_t *json_value = json_null();
	g_assert(json_value != NULL); // TODO: Runtime error

	JsonState *js = borrow_current_state(sp, global);
	bool success = key_path_insert(js->json, key, json_value, &error);
	return_current_state(js);

	json_decref(json_value);

	if( !success ) {
		g_assert(error != NULL);
		vmod_json_set_gerror(sp, global, error);
		return;
	}
}

void vmod_remove(struct sess *ign25, struct vmod_priv *ign26, const char *ign28) {
	(void) ign28, (void) ign26, (void) ign25;
	// TODO
	g_assert_not_reached();
}

// I don't recommend calling this in the global scope due to threading issues.
void vmod_clear( struct sess *sp, struct vmod_priv *global ) {
	JsonState *js = borrow_current_state(sp, global);
	json_decref(js->json);
	js->json = json_object();
	g_assert(js->json != NULL);
	return_current_state(js);
}

unsigned vmod_did_error( struct sess *sp, struct vmod_priv *global ) {
	return get_local_state(sp, global)->error != NULL;
}

const char *vmod_error_message( struct sess *sp, struct vmod_priv *global ) {
	// TODO: Verify that an error has occurred.
	return WS_Dup(sp->wrk->ws, get_local_state(sp, global)->error->message);
}

const char *vmod_error_domain( struct sess *sp, struct vmod_priv *global ) {
	// TODO: Verify that an error has occurred.
	return WS_Dup(sp->wrk->ws, g_quark_to_string(get_local_state(sp, global)->error->domain));
}

int vmod_error_code( struct sess *sp, struct vmod_priv *global ) {
	// TODO: Verify that an error has occurred.
	return get_local_state(sp, global)->error->code;
}

void vmod_error_clear( struct sess *sp, struct vmod_priv *global ) {
	// TODO: Verify that an error has occurred.
	g_error_free(get_local_state(sp, global)->error);
}

const char *vmod_to_json( struct sess *sp, struct vmod_priv *global, const char *key ) {
	GError *error = NULL;

	JsonState *js = borrow_current_state(sp, global);
	json_t *json = key_path_get(js->json, key, &error);
	return_current_state(js);
	if( json == NULL ) {
		g_assert(error != NULL);
		vmod_json_set_gerror(sp, global, error);
		return NULL;
	}

	char *json_str = json_dumps(json, 0);
	json_decref(json);
	char *ret = WS_Dup(sp->wrk->ws, json_str);
	free(json_str);
	// TODO: Error on NULL
	return ret;
}
