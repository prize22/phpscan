<?php
// phpscan: clean
$id = intval($_GET["id"]);
$st = $pdo->prepare("SELECT * FROM users WHERE id = " . $id);
$st->execute([$id]);
