<?php
// phpscan: clean
$data = json_decode($_POST["state"], true);
$state = filter_var($_GET["id"], FILTER_VALIDATE_INT);
if ($state === false) { $state = 0; }
$q = $pdo->prepare("SELECT * FROM t WHERE id = :id");
$q->execute(array(":id" => $state));
echo htmlspecialchars($_SERVER["HTTP_USER_AGENT"]);
