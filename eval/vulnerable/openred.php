<?php
// phpscan: expect: Open Redirect
$h = $_GET["url"];
header("Location: http://example.com/target.php?next=" . $h);
