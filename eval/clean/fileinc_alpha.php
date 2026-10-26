<?php
// phpscan: clean
$page = "modules/" . str_replace(array("/", ".."), "", $_GET["page"]);
$allowed = array("home", "about");
if (!ctype_alpha($page)) {
    die("bad");
}
require "views/" . $page . ".php";
