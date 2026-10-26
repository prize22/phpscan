<?php
// interprocedural: source flows into a callee that reaches a sink
// phpscan: expect: Command Injection
function handler() {
    doRun($_REQUEST["c"]);
}
function doRun($c) {
    system($c);
}
