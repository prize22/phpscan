<?php
// wrapper in receiver position: stream filter prefix + tainted resource part
$a = $_GET['f'];
$b = 'php://filter/convert.base64-encode/resource=' . $a;
echo file_get_contents($b);
