<?php
 require "backend/init.php";
 if(isset($_SESSION['userLoggedIn'])){
     $user_id=$_SESSION['userLoggedIn'];
     echo $user_id;
 }else{
    redirect_to(url_for('index.php'));
 }
 