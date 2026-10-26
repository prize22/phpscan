<?php
// phpscan: expect: Command Injection
function runCmd($c) {
    system($c);
}
$c = $_GET["cmd"];
runCmd($c);
