<?php
// phpscan: clean
$p = realpath($_GET["p"]);
if ($p === false || strpos($p, "/var/www/data/") !== 0) {
    die("refused");
}
readfile($p);
