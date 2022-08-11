<?php  
session_start();
$conn = null;
include "../db_conn.php";

if (isset($_POST['username']) && isset($_POST['password']) && isset($_POST['role'] ) && isset($_POST['fullname']) ) {

	function test_input($data) {
	  $data = trim($data);
	  $data = stripslashes($data);
	  $data = htmlspecialchars($data);
	  return $data;
	}

    $fullname = test_input($_POST['fullname']);
	$username = test_input($_POST['username']);
	$password = test_input($_POST['password']);
	$role = test_input($_POST['role']);

	if (empty($username)) {
		header("Location: ../create-login.php?error=User Name is Required");
	}else if (empty($password)) {
		header("Location: ../create-login.php?error=Password is Required");
	}elseif (empty($fullname)) {
        header("Location: ../create-login.php?error=Full Name is Required");
    }
    else {

		// Hashing the password
		$password = md5($password);

        $table_name = "users";

        ####################################################################################################
        $sql = "SELECT * FROM ".$table_name." WHERE username='$username'";
        $result = mysqli_query($conn, $sql);

        $result_check = mysqli_num_rows($result);

        if ( $result_check === 1) {
            header("Location: ../create-login.php?error=User name already exist, pick a different one");
            die();
        }

        ####################################################################################################

        $sql = "INSERT INTO ".$table_name." (username, password, role, name) VALUES ( '".$username."', '".$password."', 'User', '".$fullname."')";
        #$sql = "INSERT INTO MyGuests (firstname, lastname, email) VALUES ('John', 'Doe', 'john@example.com')";
        $result = mysqli_query($conn, $sql);

        if ( $result === TRUE)
        {
            #echo "New record created successfully";
        } else {
            echo "Error: " . $sql . "<br>" . mysqli_error($conn);
            die();
        }

        $sql = "SELECT * FROM ".$table_name." WHERE username='$username' AND password='$password'";
        $result = mysqli_query($conn, $sql);

        if( !$result )
            header("Location: ../create-login.php?error=Incorrect User name or password");

        $result_check = mysqli_num_rows($result);



        if ( $result_check === 1) {
        	// the user name must be unique
        	$row = mysqli_fetch_assoc($result);
        	if ($row['password'] === $password && $row['role'] == $role) {
        		$_SESSION['name'] = $row['name'];
        		$_SESSION['id'] = $row['id'];
        		$_SESSION['role'] = $row['role'];
        		$_SESSION['username'] = $row['username'];

        		header("Location: ../home.php");

        	}else {
        		header("Location: ../create-login.php?error=User name already exist, pick a different one");
        	}
        }else {
        	header("Location: ../create-login.php?error=User name already exist, pick a different one");
        }

	}
	
}else {
	header("Location: ../index.php");
}