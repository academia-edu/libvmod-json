# Introduction

libvmod-json is a [varnish][varnish] [vcl][vcl] module for creating JSON strings

# Usage

libvmod-json makes available a series of functions used to create a json
structure stored internally, and a `to_json` function to convert that internal
structore to a string.

## Key Paths

libvmod-json introduces a concept called a _key path_ which is used to refer to
structures inside of the json state. A key path is a string which specifies a
path to a leaf node in your expected json tree. Interior nodes are created
automatically.

The root of the internal json state is always a single json object, accessible
by the empty string. Therefore all key paths always start with object access.

### Key Path Operations

Key paths are composed of zero or more operations concatenated together. They
are of the following form:

| Operation     | String          | Description                                         |
| ------------- | --------------- | --------------------------------------------------- |
| object access | `.<identifier>` | Access the field named `<identifier>` of the object |
| array access  | `[<index>]`     | Access the array element `<index>` of the array     |
| array append  | `[<]`           | Append to the array                                 |
| array prepend | `[>]`           | Prepend to the array                                |

For array access operations, arrays automatically grow to their indexed size and
are filled with `null`.

### Example Key Paths and Their Equivalent JSON

* `.foo`: `{"foo": ...}`
* `.foo.bar`: `{"foo": {"bar": ...}}`
* `.foo[1]`: `{"foo": [null, ...]}`
* `.foo[<][1]`: `{"foo": [[null, ...]]}`
* `.foo[<][1].baz.foobaz[3]`: `{"foo": [[null, {"baz": {"foobaz": [null, null, null, ...]}}]]}`

## Scoping

There are two scopes for the internal json structure:

* local scope: the internal json structure will be reset on every request
* global scope: the internal structure will be shared among all requests

## Functions

For now, refer to [vmod_json.vcc][vmod_json_vcc]

# Future Work

Currently, libvmod-json only supports generating json strings. It can in the
future support parsing json strings, at which point it would also be a superset
of the functionality of [libvmod-var][libvmod-var]

The way local variables are implemented will need to be rewritten for varnish 4

[varnish]: https://www.varnish-cache.org/
[vcl]: https://www.varnish-cache.org/docs/3.0/reference/vcl.html
[vmod_json_vcc]: https://github.com/academia-edu/libvmod-json/blob/master/src/vmod_json.vcc
[libvmod-var]: https://github.com/varnish/libvmod-var

<!--- vim: set noet tw=80: -->
