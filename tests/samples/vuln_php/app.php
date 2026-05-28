<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysqli_query($conn, $query);

echo $_GET['name'];
system($_POST['cmd']);
readfile($_GET['page']);
eval($_POST['code']);
include $_GET['template'];
$profile = unserialize($_COOKIE['profile']);
?>
