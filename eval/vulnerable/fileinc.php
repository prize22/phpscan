<?php
// phpscan: expect: File Inclusion
$h = $_GET["page"];
include $h;
