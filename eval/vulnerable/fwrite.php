<?php
// phpscan: expect: Arbitrary File Write
$h = $_GET["dest"];
file_put_contents($h, "data");
