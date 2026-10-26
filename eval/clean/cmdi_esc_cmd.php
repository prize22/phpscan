<?php
// phpscan: clean
// sanitizer after catenation must still be honored if it covers the
// full string that reaches the sink
$arg = escapeshellcmd($_GET["x"]);
passthru("ls " . $arg);
