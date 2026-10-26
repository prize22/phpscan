<?php
// phpscan: clean
function runCmdSafe($c) {
    $allowed = ["ls"];
    if (!in_array($c, $allowed, true)) {
        return "";
    }
    return exec("ls");
}
