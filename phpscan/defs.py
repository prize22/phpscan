"""Built-in security registries: sources, sinks, sanitizers.

All registry data is extensible through YAML rules (rules.py); these
defaults are the shipped baseline and carry the context semantics consumed
by the Validation Gate.
"""

from __future__ import annotations

LVL_NONE = 0
LVL_INDIRECT = 1
LVL_TAINTED = 2

LEVEL_NAMES = {
    LVL_TAINTED: "DIRECT_USER_INPUT",
    LVL_INDIRECT: "POTENTIALLY_USER_CONTROLLED",
    LVL_NONE: "INTERNAL_DATA",
}

TAINTED_CONTEXTS = {
    "_GET": LVL_TAINTED,
    "_POST": LVL_TAINTED,
    "_REQUEST": LVL_TAINTED,
    "_COOKIE": LVL_TAINTED,
    "_FILES": LVL_TAINTED,
    "_SESSION": LVL_TAINTED,
    "HTTP_RAW_POST_DATA": LVL_TAINTED,
    "argv": LVL_INDIRECT,
    "argc": LVL_NONE,
    "_ENV": LVL_INDIRECT,
    "_SERVER": LVL_INDIRECT,
}

SERVER_SAFE_KEYS = {
    "remote_addr",
    "remote_host",
    "remote_port",
    "server_addr",
    "server_name",
    "server_port",
    "server_software",
    "server_protocol",
    "server_admin",
    "server_signature",
    "document_root",
    "https",
    "tls",
    "ssl_cipher",
}

SERVER_SENSITIVE_KEYS = {
    "request_uri",
    "query_string",
    "request_method",
    "path_info",
    "php_auth_user",
    "php_auth_pw",
    "http_authorization",
    "content_type",
    "content_length",
    "http_user_agent",
    "http_referer",
    "http_host",
    "http_cookie",
    "http_accept",
    "http_accept_language",
    "http_accept_encoding",
    "http_if_modified_since",
    "http_if_none_match",
    "http_x_requested_with",
    "http_x_forwarded_for",
    "http_x_forwarded_host",
    "http_x_forwarded_proto",
    "orig_path_info",
    "x_original_url",
    "request_body",
}

SINKS = {
    "Command Injection": {
        "funcs": {
            "exec": 0,
            "system": 0,
            "shell_exec": 0,
            "passthru": 0,
            "proc_open": 0,
            "popen": 0,
            "pcntl_exec": 0,
        },
        "method_args": {
            "popen": 0,
        },
        "cwe": "CWE-78",
        "owasp": "A03",
        "base_severity": "HIGH",
    },
    "Code Injection": {
        "funcs": {
            "eval": 0,
            "assert": 0,
            "create_function": 2,
            "dl": 0,
        },
        "method_args": {},
        "cwe": "CWE-94",
        "owasp": "A03",
        "base_severity": "CRITICAL",
    },
    "SQL Injection": {
        "funcs": {
            "mysql_query": 0,
            "mysql_db_query": 1,
            "mysqli_query": 1,
            "mysqli_real_query": 1,
            "mysqli_prepare": 1,
            "pg_query": 1,
            "pg_prepare": 1,
            "sqlite_query": 1,
            "sqlite_exec": 1,
            "odbc_exec": 1,
            "ibase_query": 1,
            "mssql_query": 1,
        },
        "method_args": {
            "query": 0,
            "raw": 0,
            "exec": 0,
            "real_query": 0,
            "statement": 0,
            "sqlquery": 0,
            "getrow": 0,
            "prepare": 0,
        },
        "cwe": "CWE-89",
        "owasp": "A03",
        "base_severity": "HIGH",
    },
    "File Inclusion": {
        "funcs": {},
        "method_args": {},
        "cwe": "CWE-98",
        "owasp": "A01",
        "base_severity": "CRITICAL",
    },
    "Path Traversal": {
        "funcs": {
            "file_get_contents": 0,
            "readfile": 0,
            "file": 0,
            "fopen": 0,
            "unlink": 0,
            "rename": 0,
            "copy": 0,
            "mkdir": 0,
            "rmdir": 0,
            "touch": 0,
            "file_exists": 0,
            "is_file": 0,
            "is_dir": 0,
            "is_readable": 0,
            "is_writable": 0,
            "filemtime": 0,
            "filesize": 0,
            "stat": 0,
            "lstat": 0,
            "chdir": 0,
            "opendir": 0,
            "glob": 0,
            "tempnam": 0,
            "realpath": -1,
            "hash_file": 0,
            "mime_content_type": 0,
            "getimagesize": 0,
            "parse_ini_file": 0,
            "gzopen": 0,
            "readgzfile": 0,
        },
        "method_args": {
            "loadfile": 0,
            "downloadfile": 0,
            "deletefile": 0,
        },
        "cwe": "CWE-22",
        "owasp": "A01",
        "base_severity": "HIGH",
    },
    "Arbitrary File Write": {
        "funcs": {
            "file_put_contents": 0,
            "move_uploaded_file": 1,
            "copy": 1,
            "rename": 1,
            "link": 1,
            "symlink": 1,
        },
        "method_args": {
            "write": 0,
            "savefile": 0,
        },
        "cwe": "CWE-73",
        "owasp": "A01",
        "base_severity": "HIGH",
    },
    "Server-Side Request Forgery": {
        "funcs": {
            "get_headers": 0,
            "fsockopen": 0,
            "stream_socket_client": 0,
            "curl_init": 0,
            "curl_exec": 0,
        },
        "method_args": {},
        "cwe": "CWE-918",
        "owasp": "A10",
        "base_severity": "HIGH",
    },
    "Insecure Deserialization": {
        "funcs": {
            "unserialize": 0,
        },
        "method_args": {
            "unserialize": 0,
        },
        "cwe": "CWE-502",
        "owasp": "A08",
        "base_severity": "HIGH",
    },
    "Open Redirect": {
        "funcs": {},
        "method_args": {
            "redirect": 0,
            "redirectto": 0,
            "location": 0,
        },
        "cwe": "CWE-601",
        "owasp": "A01",
        "base_severity": "MEDIUM",
    },
}

SANITIZERS = {
    "escapeshellarg": {"ctx": "shell", "strength": "strong"},
    "escapeshellcmd": {"ctx": "shell", "strength": "medium"},
    "htmlspecialchars": {"ctx": "html", "strength": "strong"},
    "htmlentities": {"ctx": "html", "strength": "strong"},
    "strip_tags": {"ctx": "html", "strength": "medium"},
    "html_decode_entities": {"ctx": "html", "strength": "weak"},
    "intval": {"ctx": "numeric", "strength": "strong"},
    "floatval": {"ctx": "numeric", "strength": "strong"},
    "doubleval": {"ctx": "numeric", "strength": "strong"},
    "abs": {"ctx": "numeric", "strength": "strong"},
    "floor": {"ctx": "numeric", "strength": "strong"},
    "ceil": {"ctx": "numeric", "strength": "strong"},
    "round": {"ctx": "numeric", "strength": "strong"},
    "number_format": {"ctx": "numeric", "strength": "strong"},
    "ctype_digit": {"ctx": "numeric", "strength": "strong"},
    "ctype_alpha": {"ctx": "alpha", "strength": "strong"},
    "is_numeric": {"ctx": "numeric", "strength": "strong"},
    "addslashes": {"ctx": "sql", "strength": "weak"},
    "mysql_real_escape_string": {"ctx": "sql", "strength": "medium"},
    "mysqli_real_escape_string": {"ctx": "sql", "strength": "medium"},
    "pg_escape_string": {"ctx": "sql", "strength": "medium"},
    "urlencode": {"ctx": "url", "strength": "medium"},
    "rawurlencode": {"ctx": "url", "strength": "strong"},
    "realpath": {"ctx": "path", "strength": "medium"},
    "basename": {"ctx": "path", "strength": "weak"},
    "filter_var": {"ctx": "generic", "strength": "context"},
    "filter_input": {"ctx": "generic", "strength": "context"},
}

FILTER_VAR_VALIDATORS = {
    "filter_validate_email": {"ctx": "email", "strength": "strong"},
    "filter_validate_int": {"ctx": "numeric", "strength": "strong"},
    "filter_validate_float": {"ctx": "numeric", "strength": "strong"},
    "filter_validate_ip": {"ctx": "ip", "strength": "strong"},
    "filter_validate_url": {"ctx": "url", "strength": "weak"},
    "filter_validate_regexp": {"ctx": "regex", "strength": "strong"},
    "filter_sanitize_special_chars": {"ctx": "html", "strength": "medium"},
    "filter_sanitize_string": {"ctx": "html", "strength": "weak"},
}

CAST_SANE = {"int", "integer", "float", "double", "bool", "boolean"}

TRANSFORMS = {
    "str_rot13",
    "base64_decode",
    "base64_encode",
    "gzinflate",
    "gzuncompress",
    "gzdecode",
    "hex2bin",
    "bin2hex",
    "pack",
    "unpack",
    "strrev",
    "substr",
    "trim",
    "strtolower",
    "strtoupper",
    "ucfirst",
    "str_replace",
    "preg_replace",
    "preg_replace_callback",
    "sprintf",
    "vsprintf",
    "mb_convert_encoding",
    "iconv",
    "html_entity_decode",
    "rawurldecode",
    "urldecode",
    "utf8_decode",
    "implode",
    "join",
    "str_pad",
    "str_repeat",
    "wordwrap",
    "nl2br",
    "strtr",
    "chunk_split",
    "convert_uudecode",
    "md5",
    "sha1",
    "base_convert",
    "chr",
    "ord",
    "json_encode",
    "json_decode",
    "serialize",
    "date",
    "substr_count",
}

PASSTHROUGH_PREFIXES = ("str_", "mb_", "iconv", "ctype_", "html_entity", "preg_", "base64", "bc")

WILDCARD_TAINT_FUNCS = {"extract", "import_request_variables"}

DYN_DISPATCH_FUNCS = {
    "call_user_func",
    "call_user_func_array",
    "forward_static_call",
    "forward_static_call_array",
    "dynamic_call",
}

#: Forwarding marker: "every argument after the callable index".
REST = "rest"

# Callable-consuming APIs: name -> (callable arg index, forwarding map).
#
# The forwarding map states how caller data reaches the callable's
# parameters, as a tuple of (outer argument index, callee parameter index)
# pairs.  REST expands to every argument after the callable, all landing in
# parameter 0 (element-wise feeds such as array_map are unary per element).
# An empty map means the API forwards no caller argument into the callable
# (the callable's parameters are API-supplied, e.g. an error handler's
# errno/errstring), so only an attacker-controlled callable itself matters.
#
# Constant callables resolve to builtin sinks (system, exec, ...) and to
# analyzed functions (interprocedural summary replay); tainted callables
# stay a Code Injection candidate, exactly like call_user_func.
CALLBACK_FUNCS = {
    "array_map": (0, ((REST, 0),)),
    "array_filter": (1, ((0, 0),)),
    "array_reduce": (1, ((0, 1), (2, 0))),
    "array_walk": (1, ((0, 0), (2, 2))),
    "array_walk_recursive": (1, ((0, 0), (2, 2))),
    "usort": (1, ((0, 0),)),
    "uasort": (1, ((0, 0),)),
    "uksort": (1, ((0, 0),)),
    "preg_replace_callback": (1, ((2, 0),)),
    "mb_ereg_replace_callback": (1, ((2, 0),)),
    "register_shutdown_function": (0, ((REST, 0),)),
    "ob_start": (0, ()),
    "set_error_handler": (0, ()),
    "set_exception_handler": (0, ()),
    "spl_autoload_register": (0, ()),
}

# constants whose value the engine may treat as a known literal string
KNOWN_STRING_CONSTS = {
    "__DIR__",
    "__FILE__",
    "DIRECTORY_SEPARATOR",
    "PHP_EOL",
    "PHP_VERSION",
}

# $_FILES[...][KEY] semantics: server-provided vs attacker-controlled
FILES_OK_KEYS = {"tmp_name", "error"}
FILES_INPUT_KEYS = {"name", "type", "size"}

# functions whose result becomes attacker-tainted input
SOURCE_PRODUCERS = {
    "file_get_contents": "php://input",
    "stream_get_contents": "stdin",
}
