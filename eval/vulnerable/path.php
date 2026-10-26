<?php
// phpscan: expect: Path Traversal
$h = $_GET["p"];
$f = fopen("/var/log/app/" . $h, "r");
