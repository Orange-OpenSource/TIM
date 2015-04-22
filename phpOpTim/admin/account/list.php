<?php
echo "<div class='table1' style='width:600px;height:150px;'>";

echo "<table border=1 >"; 
echo "<tr>";
echo "<td><b>Id</b></td>";
echo "<td><b>Name</b></td>";
echo "<td><b>Enabled</b></td>";
echo "<td><b>Login</b></td>";
echo "<td><b></b></td>";
echo "<td><b></b></td>";
echo "</tr>";
$result = mysql_query("SELECT * FROM `account`") or trigger_error(mysql_error());
while($row = mysql_fetch_array($result)){ 
foreach($row AS $key => $value) { $row[$key] = stripslashes($value); } 
echo "<tr>";
echo "<td valign='top'>" . nl2br( $row['id']) . "</td>";
echo "<td valign='top'>" . nl2br( $row['name']) . "</td>";
echo "<td valign='top'>" . nl2br( $row['enabled']) . "</td>";
echo "<td valign='top'>" . nl2br( $row['login']) . "</td>";  
echo "<td valign='top'><a href='index.php?action=edit&id={$row['id']}'>Edit</a></td><td><a href='index.php?action=delete&id={$row['id']}'>Delete</a></td> ";
echo "</tr>"; 
} 
echo "</table>";
echo "<br/><a href='index.php?action=new'>New Row</a>";

echo "</div>";

?>