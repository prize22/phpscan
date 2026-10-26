<?php
// phpscan: expect: Server-Side Request Forgery
$h = $_GET["host"];
$ch = curl_init("http://" . $h . "/status");
