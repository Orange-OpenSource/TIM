<?php
if (isset($_GET['id']) ) {
$id = (int) $_GET['id']; 
if (isset($_POST['submitted'])) {
foreach($_POST AS $key => $value) { $_POST[$key] = mysql_real_escape_string($value); }

if($_POST['crypted_password']) {
    $_POST['crypted_password'] = sha1($_POST['crypted_password']);
    $sql = "UPDATE `account` SET  `name` =  '{$_POST['name']}' ,  `enabled` =  '{$_POST['enabled']}' ,  `login` =  '{$_POST['login']}' ,  `crypted_password` =  '{$_POST['crypted_password']}' ,  `name_ja_kana_jp` =  '{$_POST['name_ja_kana_jp']}' ,  `name_ja_hani_jp` =  '{$_POST['name_ja_hani_jp']}' ,  `given_name` =  '{$_POST['given_name']}' ,  `given_name_ja_kana_jp` =  '{$_POST['given_name_ja_kana_jp']}' ,  `given_name_ja_hani_jp` =  '{$_POST['given_name_ja_hani_jp']}' ,  `family_name` =  '{$_POST['family_name']}' ,  `family_name_ja_kana_jp` =  '{$_POST['family_name_ja_kana_jp']}' ,  `family_name_ja_hani_jp` =  '{$_POST['family_name_ja_hani_jp']}' ,  `middle_name` =  '{$_POST['middle_name']}' ,  `middle_name_ja_kana_jp` =  '{$_POST['middle_name_ja_kana_jp']}' ,  `middle_name_ja_hani_jp` =  '{$_POST['middle_name_ja_hani_jp']}' ,  `nickname` =  '{$_POST['nickname']}' ,  `preferred_username` =  '{$_POST['preferred_username']}' ,  `profile` =  '{$_POST['profile']}' ,  `picture` =  '{$_POST['picture']}' ,  `website` =  '{$_POST['website']}' ,  `email` =  '{$_POST['email']}' ,  `email_verified` =  '{$_POST['email_verified']}' ,  `gender` =  '{$_POST['gender']}' ,  `birthdate` =  '{$_POST['birthdate']}' ,  `zoneinfo` =  '{$_POST['zoneinfo']}' ,  `locale` =  '{$_POST['locale']}' ,  `phone_number` =  '{$_POST['phone_number']}' ,  `phone_number_verified` =  '{$_POST['phone_number_verified']}' ,  `address` =  '{$_POST['address']}' ,  `updated_at` =  '{$_POST['updated_at']}'   WHERE `id` = '$id' ";
}
else
    $sql = "UPDATE `account` SET  `name` =  '{$_POST['name']}' ,  `enabled` =  '{$_POST['enabled']}' ,  `login` =  '{$_POST['login']}' ,  `name_ja_kana_jp` =  '{$_POST['name_ja_kana_jp']}' ,  `name_ja_hani_jp` =  '{$_POST['name_ja_hani_jp']}' ,  `given_name` =  '{$_POST['given_name']}' ,  `given_name_ja_kana_jp` =  '{$_POST['given_name_ja_kana_jp']}' ,  `given_name_ja_hani_jp` =  '{$_POST['given_name_ja_hani_jp']}' ,  `family_name` =  '{$_POST['family_name']}' ,  `family_name_ja_kana_jp` =  '{$_POST['family_name_ja_kana_jp']}' ,  `family_name_ja_hani_jp` =  '{$_POST['family_name_ja_hani_jp']}' ,  `middle_name` =  '{$_POST['middle_name']}' ,  `middle_name_ja_kana_jp` =  '{$_POST['middle_name_ja_kana_jp']}' ,  `middle_name_ja_hani_jp` =  '{$_POST['middle_name_ja_hani_jp']}' ,  `nickname` =  '{$_POST['nickname']}' ,  `preferred_username` =  '{$_POST['preferred_username']}' ,  `profile` =  '{$_POST['profile']}' ,  `picture` =  '{$_POST['picture']}' ,  `website` =  '{$_POST['website']}' ,  `email` =  '{$_POST['email']}' ,  `email_verified` =  '{$_POST['email_verified']}' ,  `gender` =  '{$_POST['gender']}' ,  `birthdate` =  '{$_POST['birthdate']}' ,  `zoneinfo` =  '{$_POST['zoneinfo']}' ,  `locale` =  '{$_POST['locale']}' ,  `phone_number` =  '{$_POST['phone_number']}' ,  `phone_number_verified` =  '{$_POST['phone_number_verified']}' ,  `address` =  '{$_POST['address']}' ,  `updated_at` =  '{$_POST['updated_at']}'   WHERE `id` = '$id' ";


//$sql = "UPDATE `account` SET  `name` =  '{$_POST['name']}' ,  `enabled` =  '{$_POST['enabled']}' ,  `login` =  '{$_POST['login']}' ,  `crypted_password` =  '{$_POST['crypted_password']}' ,  `name_ja_kana_jp` =  '{$_POST['name_ja_kana_jp']}' ,  `name_ja_hani_jp` =  '{$_POST['name_ja_hani_jp']}' ,  `given_name` =  '{$_POST['given_name']}' ,  `given_name_ja_kana_jp` =  '{$_POST['given_name_ja_kana_jp']}' ,  `given_name_ja_hani_jp` =  '{$_POST['given_name_ja_hani_jp']}' ,  `family_name` =  '{$_POST['family_name']}' ,  `family_name_ja_kana_jp` =  '{$_POST['family_name_ja_kana_jp']}' ,  `family_name_ja_hani_jp` =  '{$_POST['family_name_ja_hani_jp']}' ,  `middle_name` =  '{$_POST['middle_name']}' ,  `middle_name_ja_kana_jp` =  '{$_POST['middle_name_ja_kana_jp']}' ,  `middle_name_ja_hani_jp` =  '{$_POST['middle_name_ja_hani_jp']}' ,  `nickname` =  '{$_POST['nickname']}' ,  `preferred_username` =  '{$_POST['preferred_username']}' ,  `profile` =  '{$_POST['profile']}' ,  `picture` =  '{$_POST['picture']}' ,  `website` =  '{$_POST['website']}' ,  `email` =  '{$_POST['email']}' ,  `email_verified` =  '{$_POST['email_verified']}' ,  `gender` =  '{$_POST['gender']}' ,  `birthdate` =  '{$_POST['birthdate']}' ,  `zoneinfo` =  '{$_POST['zoneinfo']}' ,  `locale` =  '{$_POST['locale']}' ,  `phone_number` =  '{$_POST['phone_number']}' ,  `phone_number_verified` =  '{$_POST['phone_number_verified']}' ,  `address` =  '{$_POST['address']}' ,  `updated_at` =  '{$_POST['updated_at']}'   WHERE `id` = '$id' ";
mysql_query($sql) or die(mysql_error()); 
echo (mysql_affected_rows()) ? "Edited row.<br />" : "Nothing changed. <br />"; 
echo "<a href='index.php?action=list'>Back To Listing</a>";
} 
$row = mysql_fetch_array ( mysql_query("SELECT * FROM `account` WHERE `id` = '$id' "));

?>

<form action='' method='POST'>
<div class='table1'>
<table border='1'>
<tr>
<td><b>Field</b></td>
<td><b>Value</b></td>
</tr>


<tr><td>Name:</td><td><input type='text' name='name' value='<?= stripslashes($row['name']) ?>' /> </td></tr>
<tr><td>Enabled:</td><td><input type='text' name='enabled' value='<?= stripslashes($row['enabled']) ?>' /> </td></tr>
<tr><td>Login:</td><td><input type='text' name='login' value='<?= stripslashes($row['login']) ?>' /> </td></tr>
<tr><td>Password:</td><td><input type='text' name='crypted_password' value='' /> </td></tr>
<tr><td>Name Ja Kana Jp:</td><td><input type='text' name='name_ja_kana_jp' value='<?= stripslashes($row['name_ja_kana_jp']) ?>' /> </td></tr>
<tr><td>Name Ja Hani Jp:</td><td><input type='text' name='name_ja_hani_jp' value='<?= stripslashes($row['name_ja_hani_jp']) ?>' /> </td></tr>
<tr><td>Given Name:</td><td><input type='text' name='given_name' value='<?= stripslashes($row['given_name']) ?>' /> </td></tr>
<tr><td>Given Name Ja Kana Jp:</td><td><input type='text' name='given_name_ja_kana_jp' value='<?= stripslashes($row['given_name_ja_kana_jp']) ?>' /> </td></tr>
<tr><td>Given Name Ja Hani Jp:</td><td><input type='text' name='given_name_ja_hani_jp' value='<?= stripslashes($row['given_name_ja_hani_jp']) ?>' /> </td></tr>
<tr><td>Family Name:</td><td><input type='text' name='family_name' value='<?= stripslashes($row['family_name']) ?>' /> </td></tr>
<tr><td>Family Name Ja Kana Jp:</td><td><input type='text' name='family_name_ja_kana_jp' value='<?= stripslashes($row['family_name_ja_kana_jp']) ?>' /> </td></tr>
<tr><td>Family Name Ja Hani Jp:</td><td><input type='text' name='family_name_ja_hani_jp' value='<?= stripslashes($row['family_name_ja_hani_jp']) ?>' /> </td></tr>
<tr><td>Middle Name:</td><td><input type='text' name='middle_name' value='<?= stripslashes($row['middle_name']) ?>' /> </td></tr>
<tr><td>Middle Name Ja Kana Jp:</td><td><input type='text' name='middle_name_ja_kana_jp' value='<?= stripslashes($row['middle_name_ja_kana_jp']) ?>' /> </td></tr>
<tr><td>Middle Name Ja Hani Jp:</td><td><input type='text' name='middle_name_ja_hani_jp' value='<?= stripslashes($row['middle_name_ja_hani_jp']) ?>' /> </td></tr>
<tr><td>Nickname:</td><td><input type='text' name='nickname' value='<?= stripslashes($row['nickname']) ?>' /> </td></tr>
<tr><td>Preferred Username:</td><td><input type='text' name='preferred_username' value='<?= stripslashes($row['preferred_username']) ?>' /> </td></tr>
<tr><td>Profile:</td><td><input type='text' name='profile' value='<?= stripslashes($row['profile']) ?>' /> </td></tr>
<tr><td>Picture:</td><td><input type='text' name='picture' value='<?= stripslashes($row['picture']) ?>' /> </td></tr>
<tr><td>Website:</td><td><input type='text' name='website' value='<?= stripslashes($row['website']) ?>' /> </td></tr>
<tr><td>Email:</td><td><input type='text' name='email' value='<?= stripslashes($row['email']) ?>' /> </td></tr>
<tr><td>Email Verified:</td><td><input type='text' name='email_verified' value='<?= stripslashes($row['email_verified']) ?>' /> </td></tr>
<tr><td>Gender:</td><td><input type='text' name='gender' value='<?= stripslashes($row['gender']) ?>' /> </td></tr>
<tr><td>Birthdate:</td><td><input type='text' name='birthdate' value='<?= stripslashes($row['birthdate']) ?>' /> </td></tr>
<tr><td>Zoneinfo:</td><td><input type='text' name='zoneinfo' value='<?= stripslashes($row['zoneinfo']) ?>' /> </td></tr>
<tr><td>Locale:</td><td><input type='text' name='locale' value='<?= stripslashes($row['locale']) ?>' /> </td></tr>
<tr><td>Phone Number:</td><td><input type='text' name='phone_number' value='<?= stripslashes($row['phone_number']) ?>' /> </td></tr>
<tr><td>Phone Number Verified:</td><td><input type='text' name='phone_number_verified' value='<?= stripslashes($row['phone_number_verified']) ?>' /> </td></tr>
<tr><td>Address:</td><td><input type='text' name='address' value='<?= stripslashes($row['address']) ?>' />
<tr><td>Updated At:</td><td><input type='text' name='updated_at' value='<?= stripslashes($row['updated_at']) ?>' /> </td></tr>



</table>
</div>
    <p><input type='submit' value='Edit Row' /><input type='hidden' value='1' name='submitted' />
</form>
<?php }

?>