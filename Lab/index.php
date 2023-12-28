<?php
session_start();
if(isset($_POST["nickname"])){
  $_SESSION["nickname"] = $_POST["nickname"];
}
?>
<html>
<head>
    <title>Task 7</title>
</head>
<body>
    <?php
    echo '<a  href="?file=files/about.txt" /> Home </a><br>';
    if($file=$_GET['file']){
          include($file);
        }
  if(!isset($_SESSION["nickname"])){      
      echo '<form method="POST">
              <input name="nickname" type="text" placeholder="Enter your nickname!">
              <input type="submit" value="Enter">
            </form>';
    }else{
      echo "<br>Hello ".htmlspecialchars($_SESSION["nickname"]).", how are you today ?";
    }
    ?>
</body>
</html>
