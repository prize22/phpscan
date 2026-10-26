<?php
// phpscan: expect: Insecure Deserialization
$h = $_COOKIE["state"];
unserialize($h);
