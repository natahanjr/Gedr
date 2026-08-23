<?php
$id = $_GET['id'];
echo "User: " . $id;

mysql_query("SELECT * FROM users WHERE id = " . $id);

$cmd = $_POST['cmd'];
shell_exec($cmd);

$name = $_FILES['upload']['name'];
move_uploaded_file($_FILES['upload']['tmp_name'], "uploads/" . $name);

$token = "a1b2c3d4e5f6a1b2c3d4e5f6";
?>

<!DOCTYPE html>
<html>
<body>
<script>
    document.getElementById("out").innerHTML = location.search;
    var secret = localStorage.getItem("auth_token");
    eval(secret);
</script>
</body>
</html>
