<?php
// array_map() forwards attacker input straight into a constant callable
// phpscan: expect: Command Injection
$cmd = $_GET["cmd"];
array_map("system", [$cmd]);
