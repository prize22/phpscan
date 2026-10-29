<?php
// constant callables that are not sinks: nothing here executes input
// phpscan: clean
$args = $_GET["args"];
array_map("intval", $args);
array_map("strtoupper", $args);
$rows = ["b", "a"];
usort($rows, "strcmp");
preg_replace_callback('/\d+/', "strtoupper", $_GET["s"]);
function handler($errno, $errstr) {
    return false;
}
set_error_handler("handler");
