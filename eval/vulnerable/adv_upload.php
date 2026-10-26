<?php
// upload flow: attacker-controlled destination path
$base = '/var/www/uploads/';
$dst = $base . $_FILES['f']['name'];
move_uploaded_file($_FILES['f']['tmp_name'], $dst);
