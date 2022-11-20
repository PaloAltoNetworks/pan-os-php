<?php

/*
MYSQL_ROOT_PASSWORD: MYSQL_ROOT_PASSWORD
MYSQL_DATABASE: MYSQL_DATABASE
MYSQL_USER: MYSQL_USER
MYSQL_PASSWORD: MYSQL_PASSWORD
*/


$host = "localhost";
$uname = "root";
$password = "MYSQL_ROOT_PASSWORD";
$db_name = "MYSQL_DATABASE";


// The MySQL service named in the docker-compose.yml.
$host = 'db';
#$host = "127.0.0.1";
// Database use name
$user = 'MYSQL_USER';

//database user password
$pass = 'MYSQL_PASSWORD';

// check the MySQL connection status
$conn = new mysqli($host, $user, $pass, $db_name);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} else {
    #echo "Connected to MySQL server successfully!";
}
