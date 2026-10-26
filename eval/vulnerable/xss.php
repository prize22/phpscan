<?php
// phpscan: expect: Cross-Site Scripting
$h = $_POST["text"];
echo $h;
