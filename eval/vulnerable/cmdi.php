<?php
// phpscan: expect: Command Injection
$h = $_GET["cmd"];
system($h);
