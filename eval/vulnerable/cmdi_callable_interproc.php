<?php
// constant callable resolved across a function boundary
// phpscan: expect: Command Injection
function run_each($v) {
    system($v);
}
$args = $_GET["args"];
array_map("run_each", $args);
