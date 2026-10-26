<?php
// decoding a *constant* string yields a fixed built-in, no tainted flow
$fn = base64_decode('c3lzdGVt');
$fn('ls');
