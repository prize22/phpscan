<?php
// class-based wrapper chain: self::, parent:: and object dispatch
class Model {
    public function q($sql) {
        $pdo = new PDO();
        $pdo->query($sql);
    }
    public static function route($p) {
        self::q($p);
    }
}
class Sub extends Model {
    public function go($p) {
        parent::q($p);
    }
    public function obj($p) {
        $m = new Model();
        $m->q($p);
    }
}
$s = new Sub();
$s->go($_GET['a']);
Sub::route($_GET['b']);
$s->obj($_GET['c']);
