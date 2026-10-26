<?php
// taint accumulated inside a loop body
$cmd = '';
for ($i = 0; $i < 3; $i++) {
    $cmd .= $_COOKIE['part' . $i] . ';';
}
system($cmd);
