<?php
// phpscan: expect: Code Injection
$h = $_POST["code"];
eval($h);
