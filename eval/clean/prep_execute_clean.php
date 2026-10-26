<?php
// the tainted value reaches execute() args only, never the query string
$st = $pdo->prepare('SELECT * FROM t WHERE id = ?');
$st->execute([$_GET['id']]);
