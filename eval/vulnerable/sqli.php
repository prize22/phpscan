<?php
// phpscan: expect: SQL Injection
$h = $_GET["id"];
$pdo = new PDO();
$pdo->query("SELECT * FROM users WHERE id=" . $h);
