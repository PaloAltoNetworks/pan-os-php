<?php
//These are the defined authentication environment in the db service

// The MySQL service named in the docker-compose.yml.
$host = 'db';

// Database use name
$user = 'MYSQL_USER';

//database user password
$pass = 'MYSQL_PASSWORD';

$uname = "root";
$password = "MYSQL_ROOT_PASSWORD";

$db_name = "my_db";

$conn = mysqli_connect($host, $uname, $password, $db_name);

#if (!$conn) {
#	echo "Connection Failed!";
#	exit();
#}

/*
// check the MySQL connection status
$conn = new mysqli($host, $user, $pass);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} else {
    echo "Connected to MySQL server successfully!";
}
*/
?>