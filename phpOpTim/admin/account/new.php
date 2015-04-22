<?php 
if (isset($_POST['submitted'])) {
foreach($_POST AS $key => $value) { $_POST[$key] = mysql_real_escape_string($value); }
$_POST['crypted_password'] = sha1($_POST['crypted_password']);

$sql = "INSERT INTO `account` ( `name` ,  `enabled` ,  `login` ,  `crypted_password` ,  `name_ja_kana_jp` ,  `name_ja_hani_jp` ,  `given_name` ,  `given_name_ja_kana_jp` ,  `given_name_ja_hani_jp` ,  `family_name` ,  `family_name_ja_kana_jp` ,  `family_name_ja_hani_jp` ,  `middle_name` ,  `middle_name_ja_kana_jp` ,  `middle_name_ja_hani_jp` ,  `nickname` ,  `preferred_username` ,  `profile` ,  `picture` ,  `website` ,  `email` ,  `email_verified` ,  `gender` ,  `birthdate` ,  `zoneinfo` ,  `locale` ,  `phone_number` ,  `phone_number_verified` ,  `address` ,  `updated_at`  ) VALUES(  '{$_POST['name']}' ,  '{$_POST['enabled']}' ,  '{$_POST['login']}' ,  '{$_POST['crypted_password']}' ,  '{$_POST['name_ja_kana_jp']}' ,  '{$_POST['name_ja_hani_jp']}' ,  '{$_POST['given_name']}' ,  '{$_POST['given_name_ja_kana_jp']}' ,  '{$_POST['given_name_ja_hani_jp']}' ,  '{$_POST['family_name']}' ,  '{$_POST['family_name_ja_kana_jp']}' ,  '{$_POST['family_name_ja_hani_jp']}' ,  '{$_POST['middle_name']}' ,  '{$_POST['middle_name_ja_kana_jp']}' ,  '{$_POST['middle_name_ja_hani_jp']}' ,  '{$_POST['nickname']}' ,  '{$_POST['preferred_username']}' ,  '{$_POST['profile']}' ,  '{$_POST['picture']}' ,  '{$_POST['website']}' ,  '{$_POST['email']}' ,  '{$_POST['email_verified']}' ,  '{$_POST['gender']}' ,  '{$_POST['birthdate']}' ,  '{$_POST['zoneinfo']}' ,  '{$_POST['locale']}' ,  '{$_POST['phone_number']}' ,  '{$_POST['phone_number_verified']}' ,  '{$_POST['address']}' ,  '{$_POST['updated_at']}'  ) ";
mysql_query($sql) or die(mysql_error()); 
echo "Added row.<br />"; 
echo "<a href='index.php?action=list'>Back To Listing</a>";
} 
?>

<form action='' method='POST'>
<div class='table1'>
<table border='1'>
<tr>
<td><b>Field</b></td>
<td><b>Value</b></td>
</tr>    

<tr><td>Name:</td><td><input type='text' name='name'/> </td></tr>
<tr><td>Enabled:</td><td><input type='text' name='enabled'/> </td></tr>
<tr><td>Login:</td><td><input type='text' name='login'/> </td></tr>
<tr><td>Password:</td><td><input type='text' name='crypted_password'/> </td></tr>
<tr><td>Name Ja Kana Jp:</td><td><input type='text' name='name_ja_kana_jp'/> </td></tr>
<tr><td>Name Ja Hani Jp:</td><td><input type='text' name='name_ja_hani_jp'/> </td></tr>
<tr><td>Given Name:</td><td><input type='text' name='given_name'/> </td></tr>
<tr><td>Given Name Ja Kana Jp:</td><td><input type='text' name='given_name_ja_kana_jp'/> </td></tr>
<tr><td>Given Name Ja Hani Jp:</td><td><input type='text' name='given_name_ja_hani_jp'/> </td></tr>
<tr><td>Family Name:</td><td><input type='text' name='family_name'/> </td></tr>
<tr><td>Family Name Ja Kana Jp:</td><td><input type='text' name='family_name_ja_kana_jp'/> </td></tr>
<tr><td>Family Name Ja Hani Jp:</td><td><input type='text' name='family_name_ja_hani_jp'/> </td></tr>
<tr><td>Middle Name:</td><td><input type='text' name='middle_name'/> </td></tr>
<tr><td>Middle Name Ja Kana Jp:</td><td><input type='text' name='middle_name_ja_kana_jp'/> </td></tr>
<tr><td>Middle Name Ja Hani Jp:</td><td><input type='text' name='middle_name_ja_hani_jp'/> </td></tr>
<tr><td>Nickname:</td><td><input type='text' name='nickname'/> </td></tr>
<tr><td>Preferred Username:</td><td><input type='text' name='preferred_username'/> </td></tr>
<tr><td>Profile:</td><td><input type='text' name='profile'/> </td></tr>
<tr><td>Picture:</td><td><input type='text' name='picture'/> </td></tr>
<tr><td>Website:</td><td><input type='text' name='website'/> </td></tr>
<tr><td>Email:</td><td><input type='text' name='email'/> </td></tr>
<tr><td>Email Verified:</td><td><input type='text' name='email_verified'/> </td></tr>
<tr><td>Gender:</td><td><input type='text' name='gender'/> </td></tr>
<tr><td>Birthdate:</td><td><input type='text' name='birthdate'/> </td></tr>
<tr><td>Zoneinfo:</td><td><input type='text' name='zoneinfo'/> </td></tr>
<tr><td>Locale:</td><td><input type='text' name='locale'/> </td></tr>
<tr><td>Phone Number:</td><td><input type='text' name='phone_number'/> </td></tr>
<tr><td>Phone Number Verified:</td><td><input type='text' name='phone_number_verified'/> </td></tr>
<tr><td>Address:</td><td><input type='text' name='address'/> </td></tr>
<tr><td>Updated At:</td><td><input type='text' name='updated_at'/> </td></tr>
</table>
</div>
    <br/><br/>
    <p><input type='submit' value='Add Row' /><input type='hidden' value='1' name='submitted' />

</form> 
