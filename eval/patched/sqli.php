<?php
// phpscan: clean
$st = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$st->execute([$_GET["id"]]);
