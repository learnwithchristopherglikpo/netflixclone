<?php

class Account{
    private $pdo;
    private $errorArray=[];

    public function __construct(){
        $this->pdo=Database::instance();
    }

    public function register($fn,$ln,$em,$pwd){
        $this->validateFirstName($fn);
        $this->validateLastName($ln);
        $this->validateEmail($em);
        $this->validatePassword($pwd);
        if(empty($errorArray)){
            return $this->insertUserDetails($fn,$ln,$em,$pwd);
        }else{
            return true;
        }
      

    }

    public function login($email,$pwd){
        $pass_hash=$this->getHashPassword($email);
        $stmt=$this->pdo->prepare("SELECT * FROM `users` WHERE email=:email AND password=:pwd");
        $stmt->bindParam(":email",$email,PDO::PARAM_STR);
        $stmt->bindParam(":pwd",$pass_hash,PDO::PARAM_STR);
        $stmt->execute();
        $user=$stmt->fetch(PDO::FETCH_OBJ);
        $count=$stmt->rowCount();
        if($count != 0){
            if(password_verify($pwd,$pass_hash)){
                return $user->user_id;
            }else{
                 array_push($this->errorArray,Constant::$loginFailed);
                 return false;
            }
        }else{
            array_push($this->errorArray,Constant::$loginFailed);
            return false;
        }
    }

    private function getHashPassword($email){
        $stmt=$this->pdo->prepare("SELECT `password` FROM `users` WHERE email=:email");
        $stmt->bindParam(":email",$email,PDO::PARAM_STR);
        $stmt->execute();
        $user=$stmt->fetch(PDO::FETCH_OBJ);
        $count=$stmt->rowCount();
        if($count !=0){
            return $user->password;
        }else{
            return false;
        }
    }

    public function insertUserDetails($fn,$ln,$em,$pwd){
         $pass_hash=password_hash($pwd,PASSWORD_BCRYPT);
         $stmt=$this->pdo->prepare("INSERT INTO users (firstName,lastName,email,password) VALUES (:fn,:ln,:em,:pwd)");
         $stmt->bindParam(":fn",$fn,PDO::PARAM_STR);
         $stmt->bindParam(":ln",$ln,PDO::PARAM_STR);
         $stmt->bindParam(":em",$em,PDO::PARAM_STR);
         $stmt->bindParam(":pwd",$pass_hash,PDO::PARAM_STR);

         $stmt->execute();

         return $this->pdo->lastInsertId();
       
    }

    public function validateFirstName($fn){
        if($this->length($fn,2,25)){
            return array_push($this->errorArray,Constant::$firstNameCharacters);
        }
    }
    

    public function validateLastName($ln){
        if($this->length($ln,2,25)){
            return array_push($this->errorArray,Constant::$lastNameCharacters);
        }
    } 
    
    public function validatePassword($pwd){
        if(preg_match("/[^A-Za-z0-9]/",$pwd)){
            return array_push($this->errorArray,Constant::$passwordNotAlphanumeric);
        }
        if($this->length($pwd,5,30)){
            return array_push($this->errorArray,Constant::$passwordLength);
        }
    }

    private function length($input,$min,$max){
        if(strlen($input) <$min){
            return true;
        }else if(strlen($input) > $max){
            return true;
        }
    }
    public function validateEmail($em){
        $stmt=$this->pdo->prepare("SELECT * FROM `users` WHERE email=:email");
        $stmt->bindParam(":email",$em,PDO::PARAM_STR);
        $stmt->execute();
        $count=$stmt->rowCount();
        if($count >0){
            return array_push($this->errorArray,Constant::$emailInUse);
        }

       
        if(!filter_var($em,FILTER_VALIDATE_EMAIL)){
            return array_push($this->errorArray,Constant::$emailInValid);
        }

        if(empty($this->errorArray)){
            return $em;
        }else{
            return false;
        }
    }
    
    public function getErrorMessage($error){
        if(in_array($error,$this->errorArray)){
            return "<div class='inputError'>$error</div>";
        }
    }


}