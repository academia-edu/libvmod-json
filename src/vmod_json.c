#include <config.h>

#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include <jansson.h>
#include <glib.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

#if JANSSON_MAJOR_VERSION <= 2 && JANSSON_MINOR_VERSION < 4
#define json_boolean(val) ((val) ? json_true() : json_false())
#endif

#ifndef NDEBUG
#define dbgprintf(sp, ...) VSL(SLT_VCL_trace, ((sp) == NULL ? 0 : ((struct sess *) (sp))->id), __VA_ARGS__)
#else
#define dbgprintf(sp, ...) ((void) (sp))
#endif

#ifndef LOG_PERROR
#define LOG_PERROR 0
#endif

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
	uint64_t magic;
#define JSON_MAGIC 0xa782945645a92452ULL
} JsonGlobalState;

typedef struct {
	JsonState parent;
	GError *error;
	unsigned xid;
	bool global : 1;
} JsonLocalState;

// -- prototypes

static JsonLocalState *get_local_state( struct sess *, struct vmod_priv * );

// -- error support

#define VMOD_JSON_ERROR vmod_json_error_quark()

typedef enum {
	VMOD_JSON_ERR_NONE = 0,
	VMOD_JSON_ERR_INVALID_ARGUMENTS,
	VMOD_JSON_ERR_KEY_NOT_FOUND,
	VMOD_JSON_ERR_ARRAY_OUT_OF_BOUNDS,
	VMOD_JSON_ERR_SYNTAX_NO_IDENTIFIER,
	VMOD_JSON_ERR_SYNTAX_BAD_ARRAY_INDEX,
	VMOD_JSON_ERR_SYNTAX_ARRAY_BRACKET,
	VMOD_JSON_ERR_SYNTAX_VALUE_INVALID,
	VMOD_JSON_ERR_SYNTAX_NO_OPERATION,
	VMOD_JSON_ERR_INVALID_TYPE,
	VMOD_JSON_ERR_JANSSON,
	VMOD_JSON_ERR_NOT_UTF8
} VmodJsonErrorCode;

static GQuark vmod_json_error_quark() {
	return g_quark_from_static_string("vmod-json-error-quark");
}

static void vmod_json_set_gerror( struct sess *sp, struct vmod_priv *global, GError *error ) {
	g_assert(error != NULL);
	dbgprintf(sp, "vmod_json_set_gerror: error->message = '%s'", error->message);
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
	dbgprintf(0, "init_json_state");
	g_assert(js != NULL);
	js->json = json_object();
	g_assert(js->json != NULL);
	js->type = JSON_STATE_UNSPEC;
}

static void init_json_local_state( JsonLocalState *jls, struct sess *sp ) {
	dbgprintf(sp, "init_json_local_state");
	init_json_state((JsonState *) jls);
	((JsonState *) jls)->type = JSON_STATE_LOCAL;
	jls->global = false;
	jls->error = NULL;
	jls->xid = sp->xid;
}

static void init_json_global_state( JsonGlobalState *jgs ) {
	dbgprintf(0, "init_json_global_state");
	init_json_state((JsonState *) jgs);
	((JsonState *) jgs)->type = JSON_STATE_GLOBAL;
	jgs->magic = JSON_MAGIC;
	jgs->locals = g_hash_table_new_full(
		g_direct_hash,
		g_direct_equal,
		NULL,
		(GDestroyNotify) free_json_state
	);
	g_rec_mutex_init(&jgs->lock);
}

static JsonGlobalState *new_json_global_state() {
	JsonGlobalState *jgs = g_slice_new(JsonGlobalState);
	init_json_global_state(jgs);
	return jgs;
}

static JsonLocalState *new_json_local_state( struct sess *sp ) {
	JsonLocalState *jls = g_slice_new(JsonLocalState);
	init_json_local_state(jls, sp);
	return jls;
}

int vmod_json_init( struct vmod_priv *global, const struct VCL_conf *conf ) {
	(void) conf;
	dbgprintf(0, "vmod_json_init");

	global->priv = new_json_global_state();
	global->free = (vmod_priv_free_f *) free_json_state;

	return 0;
}

static JsonGlobalState *borrow_global_state( struct vmod_priv * );
static void return_global_state( JsonGlobalState * );

/*
 * This will become easier in varnish 4.x
 *
 * From Varnish IRC
 *
 * 11:51 @Mithrandir> libvmod-var will have to be redone for 4.0, since that (sp->id) identifier isn't reused there.
 * 11:51 @Mithrandir> but I haven't had the time to do that yet.
 * 11:51  eatnumber1> which identifier, xid or fd?
 * 11:51 @Mithrandir> fd
 * 11:51 @Mithrandir> the nice thing about them being reused is you effectively bound the memory usage pretty easily.
 * 11:52  eatnumber1> it'd be nice if varnish core had facilities to hook into request setup / teardown
 * 11:52  eatnumber1> ala a PRIV_REQ argument to vmod functions
 * 11:52 @Mithrandir> it's been discussed and will happen either for 4.0 or 4.x
 */
static JsonLocalState *get_local_state( struct sess *sp, struct vmod_priv *global ) {
	dbgprintf(sp, "get_local_state: sp->id = %d, sp->xid = %d", sp->id, sp->xid);

	JsonGlobalState *jgs = borrow_global_state(global);

	gpointer *jls_key = GINT_TO_POINTER(sp->id);
	JsonLocalState *jls = g_hash_table_lookup(jgs->locals, jls_key);

	if( jls != NULL && sp->xid != jls->xid ) jls = NULL;

	if( jls == NULL ) {
		jls = new_json_local_state(sp);
		g_hash_table_replace(jgs->locals, jls_key, jls);
	}
	g_assert(jls != NULL);

	return_global_state(jgs);

	return jls;
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

static JsonState *borrow_current_state( struct sess *sp, struct vmod_priv *global ) {
	JsonLocalState *jls = get_local_state(sp, global);
	if( jls->global ) {
		dbgprintf(sp, "borrow_current_state: global");
		return (JsonState *) borrow_global_state(global);
	} else {
		dbgprintf(sp, "borrow_current_state: local");
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
	KEY_PATH_OP_UNSPEC = 0,
	KEY_PATH_OP_OBJECT_ACCESS,
	KEY_PATH_OP_ARRAY_PREPEND,
	KEY_PATH_OP_ARRAY_APPEND,
	KEY_PATH_OP_ARRAY_INDEX
} KeyPathOpType;

typedef enum {
	KEY_PATH_VALUE_UNSPEC = 0,
	KEY_PATH_VALUE_OBJECT,
	KEY_PATH_VALUE_ARRAY,
	KEY_PATH_VALUE_LEAF
} KeyPathValueType;

typedef struct {
	KeyPathOpType type;
	KeyPathValueType value_type;
	union {
		intmax_t index;
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

	dbgprintf(0, "key_path_parse_object_op: *endptr = '%s', i = %zu, *endptr + i = '%s'", *endptr, i, *endptr + i);

	if( i == 0 ) {
		g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_NO_IDENTIFIER, "No identifier specified");
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
		g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_BAD_ARRAY_INDEX, "Invalid array operator");
		return false;
	}

	switch( *array_index_buf ) {
		case '>':
			out->type = KEY_PATH_OP_ARRAY_PREPEND;
			break;
		case '<':
			out->type = KEY_PATH_OP_ARRAY_APPEND;
			break;
		default:
			g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_BAD_ARRAY_INDEX, "Invalid array operator");
			return false;
	}

#ifndef NDEBUG
	char array_index_vla[array_index_buf_len + 1];
	memcpy(array_index_vla, array_index_buf, array_index_buf_len);
	array_index_vla[array_index_buf_len] = '\0';
	dbgprintf(0, "key_path_parse_array_append_or_prepend_op: array_index_buf = '%s'", array_index_vla);
#endif

	return true;
}

static bool key_path_parse_array_index_op( const char *array_index_buf, size_t array_index_buf_len, KeyPathOp *out, GError **error ) {
	g_assert(out != NULL);

	dbgprintf(0, "key_path_parse_array_index_op: array_index_buf = '%s', array_index_buf_len = %zd", array_index_buf, array_index_buf_len);

	// Convert the num string into an intmax
	char *array_index_endptr = NULL;
	errno = 0;
	intmax_t array_index = strtoimax(array_index_buf, &array_index_endptr, 0);
	if( errno != 0 ) {
		g_set_error(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_BAD_ARRAY_INDEX, "Error converting array index to number: %s", g_strerror(errno));
		return false;
	}
	g_assert(array_index_endptr != NULL);
	if( array_index_endptr != array_index_buf + array_index_buf_len ) {
		g_set_error(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_BAD_ARRAY_INDEX, "Invalid characters found in array index: '%s'", array_index_endptr);
		return false;
	}

	// This is an annoyingly phrased check to see if
	// array_index >= -SIZE_MAX && array_index <= SIZE_MAX.
	if(
		(array_index < 0 && (uintmax_t) -(array_index + 1) > SIZE_MAX - 1) ||
		(array_index >= 0 && (uintmax_t) array_index > SIZE_MAX)
	) {
		g_set_error(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_BAD_ARRAY_INDEX, "Array index %jd out of bounds", array_index);
		return false;
	}

#ifndef NDEBUG
	char array_index_vla[array_index_buf_len + 1];
	memcpy(array_index_vla, array_index_buf, array_index_buf_len);
	array_index_vla[array_index_buf_len] = '\0';
	dbgprintf(0, "key_path_parse_array_index_op: array_index_buf = '%s', array_index = %jd", array_index_vla, array_index);
#endif

	out->type = KEY_PATH_OP_ARRAY_INDEX;
	out->value.index = array_index;
	return true;
}

static bool key_path_parse_array_op( const char *key_path, KeyPathOp *out, const char **endptr, GError **error ) {
	g_assert(out != NULL);
	g_assert(endptr != NULL);

	dbgprintf(0, "key_path_parse_array_op: key_path = '%s'", key_path);

	// Figure out the length of the array index
	size_t array_index_len = 0;
	for( array_index_len = 0; key_path[array_index_len] != ']'; array_index_len++ ) {
		if( key_path[array_index_len] == '\0' ) {
			g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_ARRAY_BRACKET, "No closing bracket in array index");
			return false;
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
			g_set_error(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_VALUE_INVALID, "Value type '%c' invalid", key_path[array_index_len + 1]);
			return false;
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
	dbgprintf(0, "key_path_parse_op: key_path = '%s'", key_path);

	switch( *key_path ) {
		case '.':
			*endptr += 1;
			return key_path_parse_object_op(key_path + 1, out, endptr, error);
		case '[':
			*endptr += 1;
			return key_path_parse_array_op(key_path + 1, out, endptr, error);
		default:
			g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_NO_OPERATION, "No operation specified");
			return false;
	}

	g_assert_not_reached();
}

typedef struct {
	json_t *(*func)( json_t *, KeyPathOp *, void *, GError ** );
	void *payload;
} KeyPathTraverser;

static bool key_path_parse( const char *key_path, json_t *top, KeyPathTraverser *traverser, GError **error ) {
	dbgprintf(0, "key_path_parse: key_path = '%s'", key_path);

	GError *err = NULL;

	const char *ptr = key_path, *endptr = key_path + strlen(key_path);
	json_t *cur = top;

	while( ptr < endptr ) {
		switch( *ptr ) {
			case '.':
			case '[': {
				KeyPathOp op;
				if( !key_path_parse_op(ptr, &op, &ptr, error) ) {
					dbgprintf(0, "key_path_parse: return false;");
					return false;
				}
				g_assert(ptr <= endptr);
#ifndef NDEBUG
				dbgprintf(0, "key_path_parse: op = {");
				dbgprintf(0, "\t.type = %d", op.type);
				dbgprintf(0, "\t.value_type = %d", op.value_type);
				switch( op.type ) {
					case KEY_PATH_OP_OBJECT_ACCESS: {
						char buf[op.value.key.buflen + 1];
						memcpy(buf, op.value.key.buf, op.value.key.buflen);
						buf[op.value.key.buflen] = '\0';
						dbgprintf(0, "\t.value.key.buf = '%s'", buf);
						break;
					}
					case KEY_PATH_OP_ARRAY_INDEX:
						dbgprintf(0, "\t.value.index = '%jd'", op.value.index);
						break;
					default:
						break;
				}
				dbgprintf(0, "};");
#endif
				cur = traverser->func(cur, &op, traverser->payload, &err);
				if( err != NULL ) {
					g_propagate_error(error, err);
					return false;
				}
				break;
			}
			default:
				g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_NO_OPERATION, "No operation specified");
				return false;
		}

#ifndef NDEBUG
		char *top_str = json_dumps(top, JSON_ENCODE_ANY);
		dbgprintf(0, "key_path_parse: iterate, top = '%s'", top_str);
		free(top_str);
#endif
	}
	traverser->func(cur, NULL, traverser->payload, &err);
	if( err != NULL ) {
		g_propagate_error(error, err);
		return false;
	}
	return true;
}

static json_t *key_path_create_or_return_value( KeyPathOp *op, json_t *value, GError **error ) {
	(void) error;

	if( value != NULL ) {
		json_incref(value);
		return value;
	}

	json_t *ret = NULL;

	switch( op->value_type ) {
		case KEY_PATH_VALUE_ARRAY:
			dbgprintf(0, "key_path_create_or_return_value: json_array()");
			ret = json_array();
			break;
		case KEY_PATH_VALUE_OBJECT:
			dbgprintf(0, "key_path_create_or_return_value: json_object()");
			ret = json_object();
			break;
		case KEY_PATH_VALUE_LEAF:
			g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_KEY_NOT_FOUND, "Key not found");
			return NULL;
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
				if( o == NULL ) return NULL;
#ifndef NDEBUG
				char *cur_str = json_dumps(cur, JSON_ENCODE_ANY), *o_str = json_dumps(o, JSON_ENCODE_ANY);
				dbgprintf(0, "key_path_get_and_insert_or_create: json_object_set('%s', '%s', '%s')", cur_str, key, o_str);
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

			size_t array_size = json_array_size(cur);
			size_t array_index = SIZE_MAX; // This should fail if we fuck up later
			{
				intmax_t index = op->value.index;
				dbgprintf(0, "key_path_get_and_insert_or_create: array_size = %zd, index = %jd", array_size, index);
				if( index < 0 ) index += array_size;
				if( index < 0 ) {
					g_set_error(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_SYNTAX_BAD_ARRAY_INDEX, "Array index %jd out of bounds", index);
					return NULL;
				}
				array_index = (size_t) index;
			}
			dbgprintf(0, "key_path_get_and_insert_or_create: array_index = %zd", array_index);
			if( array_size <= array_index ) {
				for( size_t i = array_size; i <= array_index; i++ ) {
					json_t *nul = json_null();
					g_assert(nul != NULL);
					json_array_append_new(cur, nul);
				}
			}

			ret = json_array_get(cur, array_index);
			if(
				(value != NULL && !json_equal(ret, value)) ||
				(json_is_null(ret) && op->value_type != KEY_PATH_VALUE_LEAF)
			) {
				ret = NULL;
			}
			if( ret == NULL ) {
				json_t *o = key_path_create_or_return_value(op, value, error);
				if( o == NULL ) return NULL;
#ifndef NDEBUG
				{
					char *cur_str = json_dumps(cur, JSON_ENCODE_ANY), *o_str = json_dumps(o, JSON_ENCODE_ANY);
					dbgprintf(0, "key_path_get_and_insert_or_create: json_array_set('%s', %zd, '%s') -> ", cur_str, op->value.index, o_str);
					free(cur_str), free(o_str);
				}
#endif
				int code = json_array_set(cur, array_index, o);
				g_assert(code == 0);
#ifndef NDEBUG
				{
					char *cur_str = json_dumps(cur, JSON_ENCODE_ANY);
					dbgprintf(0, "'%s'", cur_str);
					free(cur_str);
				}
#endif
				json_decref(o);
				ret = o;
			}
#ifndef NDEBUG
			char *ret_str = json_dumps(ret, JSON_ENCODE_ANY), *value_str = value == NULL ? "(null)" : json_dumps(value, JSON_ENCODE_ANY);
			dbgprintf(0, "key_path_get_and_insert_or_create: ret = '%s', value = '%s'", ret_str, value_str);
			free(ret_str);
			if( value != NULL ) free(value_str);
#endif

			break;
		case KEY_PATH_OP_ARRAY_APPEND: {
			g_assert(json_is_array(cur));

			dbgprintf(0, "key_path_get_and_insert_or_create: json_array_append(cur, value)");
			json_t *o = key_path_create_or_return_value(op, value, error);
			if( o == NULL ) return NULL;
			int code = json_array_append(cur, o);
			g_assert(code == 0);
			json_decref(o);
			ret = o;
			break;
		}
		case KEY_PATH_OP_ARRAY_PREPEND: {
			g_assert(json_is_array(cur));

			dbgprintf(0, "key_path_get_and_insert_or_create: json_array_insert(cur, 0, value)");
			json_t *o = key_path_create_or_return_value(op, value, error);
			if( o == NULL ) return NULL;
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

#ifndef NDEBUG
	char *cur_str = json_dumps(cur, JSON_ENCODE_ANY);
	dbgprintf(0, "key_path_getter_traverser: cur = '%s'", cur_str);
	free(cur_str);
#endif

	if( op == NULL ) {
		*out = cur;
		return NULL;
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
		dbgprintf(0, "key_path_get: return NULL");
		return NULL;
	}
	g_assert(value != NULL);
	json_incref(value);
	return value;
}

static json_t *key_path_setter_traverser( json_t *cur, KeyPathOp *op, json_t *value, GError **error ) {
	g_assert(cur != NULL);

#ifndef NDEBUG
	{
		char *cur_str = json_dumps(cur, JSON_ENCODE_ANY), *value_str = json_dumps(value, JSON_ENCODE_ANY);
		dbgprintf(0, "key_path_setter_traverser: cur = '%s', value = '%s'", cur_str, value_str);
		free(cur_str), free(value_str);
	}
#endif

	if( op == NULL ) {
		if( !json_equal(cur, value) )
			g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_INVALID_TYPE, "Operation performed on incompatible type");
		return NULL;
	}

	json_t *ret = NULL;
	switch( op->value_type ) {
		case KEY_PATH_VALUE_LEAF:
			ret = key_path_get_and_insert_or_create(cur, op, value, error);
			if( ret == NULL ) return NULL;
			g_assert(json_equal(value, ret));
			break;
		case KEY_PATH_VALUE_OBJECT:
		case KEY_PATH_VALUE_ARRAY:
			ret = key_path_get_and_insert_or_create(cur, op, NULL, error);
			if( ret == NULL ) return NULL;
			break;
		default:
			g_assert_not_reached();
	}
	g_assert(ret != NULL);

#ifndef NDEBUG
	{
		char *cur_str = json_dumps(cur, JSON_ENCODE_ANY), *value_str = json_dumps(value, JSON_ENCODE_ANY), *ret_str = json_dumps(ret, JSON_ENCODE_ANY);
		dbgprintf(0, "key_path_setter_traverser: cur = '%s', ret = '%s', value = '%s'", cur_str, ret_str, value_str);
		free(cur_str), free(value_str), free(ret_str);
	}
#endif

	return ret;
}

static bool key_path_insert( json_t *top, const char *key, json_t *value, GError **error ) {
	KeyPathTraverser traverser = {
		.func = (__typeof__(traverser.func)) key_path_setter_traverser,
		.payload = (void *) value
	};
	return key_path_parse(key, top, &traverser, error);
}

typedef struct {
	KeyPathOp prev_op;
	json_t *prev_json;
} KeyPathRemoverTraverserArgs;

static json_t *key_path_remover_traverser( json_t *cur, KeyPathOp *op, KeyPathRemoverTraverserArgs *args, GError **error ) {
	g_assert(cur != NULL);
	g_assert(args != NULL);

	if( op == NULL ) {
		if( args->prev_op.type == KEY_PATH_OP_UNSPEC ) {
			g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_KEY_NOT_FOUND, "Removing non-existant key");
			return NULL;
		}

		switch( args->prev_op.type ) {
			case KEY_PATH_OP_OBJECT_ACCESS: {
				g_assert(json_is_object(args->prev_json));
				// Need to copy the key since it's not null terminated in the op
				char key[args->prev_op.value.key.buflen + 1];
				memcpy(key, args->prev_op.value.key.buf, args->prev_op.value.key.buflen);
				key[args->prev_op.value.key.buflen] = '\0';

				int ret = json_object_del(args->prev_json, key);
				g_assert(ret == 0);
				break;
			}
			case KEY_PATH_OP_ARRAY_INDEX: {
				g_assert(json_is_array(args->prev_json));
				int ret = json_array_remove(args->prev_json, args->prev_op.value.index);
				g_assert(ret == 0);
				break;
			}
			case KEY_PATH_OP_ARRAY_APPEND: {
				g_assert(json_is_array(args->prev_json));
				size_t size = json_array_size(args->prev_json);
				if( size == 0 ) {
					g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_ARRAY_OUT_OF_BOUNDS, "Removing from zero sized array");
					return NULL;
				}
				int ret = json_array_remove(args->prev_json, size - 1);
				g_assert(ret == 0);
				break;
			}
			case KEY_PATH_OP_ARRAY_PREPEND: {
				g_assert(json_is_array(args->prev_json));
				size_t size = json_array_size(args->prev_json);
				if( size == 0 ) {
					g_set_error_literal(error, VMOD_JSON_ERROR, VMOD_JSON_ERR_ARRAY_OUT_OF_BOUNDS, "Removing from zero sized array");
					return NULL;
				}
				int ret = json_array_remove(args->prev_json, 0);
				g_assert(ret == 0);
				break;
			}
			default:
				g_assert_not_reached();
		}

		return NULL;
	}

	args->prev_op = *op;
	if( args->prev_json != NULL ) json_decref(args->prev_json);
	args->prev_json = json_incref(cur);

	return key_path_get_and_insert_or_create(cur, op, NULL, error);
}

static bool key_path_remove( json_t *top, const char *key, GError **error ) {
	KeyPathRemoverTraverserArgs args;
	memset(&args, 0, sizeof(args));
	KeyPathTraverser traverser = {
		.func = (__typeof__(traverser.func)) key_path_remover_traverser,
		.payload = (void *) &args
	};
	return key_path_parse(key, top, &traverser, error);
}

// -- actual vmod functions

void vmod_global( struct sess *sp, struct vmod_priv *global ) {
	dbgprintf(sp, "vmod_global");
	JsonLocalState *jls = get_local_state(sp, global);
	if( jls->error != NULL ) return;

	jls->global = true;
}

void vmod_local( struct sess *sp, struct vmod_priv *global ) {
	dbgprintf(sp, "vmod_local");
	JsonLocalState *jls = get_local_state(sp, global);
	if( jls->error != NULL ) return;

	jls->global = false;
}

void vmod_string( struct sess *sp, struct vmod_priv *global, const char *key, const char *value ) {
	GError *error = NULL;

	if( value == NULL ) {
		vmod_null(sp, global, key);
		return;
	}

	if( get_local_state(sp, global)->error != NULL ) return;

	if( !g_utf8_validate(value, -1, NULL) ) {
		// Can't put the bad string in here because g_set_error expects utf8 input.
		error = g_error_new_literal(VMOD_JSON_ERROR, VMOD_JSON_ERR_NOT_UTF8, "Cannot build json using non-UTF8 string");
		vmod_json_set_gerror(sp, global, error);
		return;
	}
	json_t *json_value = json_string(value);
	g_assert(json_value != NULL);

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

	if( get_local_state(sp, global)->error != NULL ) return;

	json_t *json_value = json_integer(value);
	g_assert(json_value != NULL);

	JsonState *js = borrow_current_state(sp, global);
	bool success = key_path_insert(js->json, key, json_value, &error);
	return_current_state(js);

	json_decref(json_value);

	if( !success ) {
		g_assert(error != NULL);
		vmod_json_set_gerror(sp, global, error);
		return;
	}

#ifndef NDEBUG
	char *json_value_str = json_dumps(json_value, JSON_ENCODE_ANY);
	dbgprintf(sp, "vmod_integer: json_value = '%s', success = %s, error = '%s'", json_value_str, success ? "true" : "false", success ? "(null)" : error->message);
	free(json_value_str);

	char *js_json_str = json_dumps(js->json, JSON_ENCODE_ANY);
	dbgprintf(sp, "vmod_integer: js->json = '%s'", js_json_str);
	free(js_json_str);
#endif
}

void vmod_real( struct sess *sp, struct vmod_priv *global, const char *key, double value ) {
	GError *error = NULL;

	if( get_local_state(sp, global)->error != NULL ) return;

	json_t *json_value = json_real(value);
	g_assert(json_value != NULL);

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

void vmod_bool( struct sess *sp, struct vmod_priv *global, const char *key, unsigned value ) {
	GError *error = NULL;

	if( get_local_state(sp, global)->error != NULL ) return;

	json_t *json_value = json_boolean(value);
	g_assert(json_value != NULL);

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

void vmod_null( struct sess *sp, struct vmod_priv *global, const char *key ) {
	GError *error = NULL;

	if( get_local_state(sp, global)->error != NULL ) return;

	json_t *json_value = json_null();
	g_assert(json_value != NULL);

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

void vmod_object( struct sess *sp, struct vmod_priv *global, const char *key ) {
	GError *error = NULL;

	if( get_local_state(sp, global)->error != NULL ) return;

	json_t *json_value = json_object();
	g_assert(json_value != NULL);

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

void vmod_array( struct sess *sp, struct vmod_priv *global, const char *key ) {
	GError *error = NULL;

	if( get_local_state(sp, global)->error != NULL ) return;

	json_t *json_value = json_array();
	g_assert(json_value != NULL);

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

void vmod_remove( struct sess *sp, struct vmod_priv *global, const char *key ) {
	GError *error = NULL;

	if( get_local_state(sp, global)->error != NULL ) return;

	JsonState *js = borrow_current_state(sp, global);
	bool success = key_path_remove(js->json, key, &error);
	return_current_state(js);

	if( !success ) {
		g_assert(error != NULL);
		vmod_json_set_gerror(sp, global, error);
		return;
	}
}

// I don't recommend calling this in the global scope due to threading issues.
void vmod_clear( struct sess *sp, struct vmod_priv *global ) {
	if( get_local_state(sp, global)->error != NULL ) return;

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
	JsonLocalState *jls = get_local_state(sp, global);
	const char *message = jls->error == NULL ? "No error" : jls->error->message;
	return WS_Dup(sp->wrk->ws, message);
}

const char *vmod_error_domain( struct sess *sp, struct vmod_priv *global ) {
	JsonLocalState *jls = get_local_state(sp, global);
	const char *message = g_quark_to_string(jls->error == NULL ? VMOD_JSON_ERROR : jls->error->domain);
	return WS_Dup(sp->wrk->ws, message);
}

int vmod_error_code( struct sess *sp, struct vmod_priv *global ) {
	JsonLocalState *jls = get_local_state(sp, global);
	int code = jls->error == NULL ? VMOD_JSON_ERR_NONE : jls->error->code;
	dbgprintf(sp, "vmod_error_code: code = %d", code);
	return code;
}

void vmod_error_clear( struct sess *sp, struct vmod_priv *global ) {
	JsonLocalState *jls = get_local_state(sp, global);
	if( jls->error != NULL ) {
		g_error_free(jls->error);
		jls->error = NULL;
	}
}

const char *vmod_dump( struct sess *sp, struct vmod_priv *global, const char *key ) {
	GError *error = NULL;

	if( get_local_state(sp, global)->error != NULL ) return NULL;

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
	g_assert(ret != NULL);
	free(json_str);

	dbgprintf(sp, "vmod_dump: ret = '%s'", ret);

	return ret;
}
