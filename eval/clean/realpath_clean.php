<?php
// realpath canonicalizes before the sink: conservative downgrade expected
$f = realpath($_GET['p']);
echo is_file($f);
