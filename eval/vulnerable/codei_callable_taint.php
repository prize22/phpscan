<?php
// attacker-controlled callable: PHP invokes whichever name arrives
// phpscan: expect: Code Injection
$rows = $_GET["rows"];
usort($rows, $_GET["cmp"]);
