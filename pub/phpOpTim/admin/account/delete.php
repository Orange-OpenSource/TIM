<?php 
$id = (int) $_GET['id'];
mysql_query("DELETE FROM `account` WHERE `id` = '$id' ") ;
echo (mysql_affected_rows()) ? "Row deleted.<br /> " : "Nothing deleted.<br /> "; 
?> 

<a href='index.php?action=list'>Back To Listing</a>
