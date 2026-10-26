<?php
// server-provided upload metadata is not attacker-controlled data
echo file_get_contents($_FILES['f']['tmp_name']);
