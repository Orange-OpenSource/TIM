<?php 
if (isset($_POST['submitted'])) {
foreach($_POST AS $key => $value) { $_POST[$key] = mysql_real_escape_string($value); } 
$sql = "INSERT INTO `client` ( `client_id_issued_at` ,  `client_id` ,  `client_secret` ,  `client_secret_expires_at` ,  `registration_access_token` ,  `registration_client_uri_path` ,  `contacts` ,  `application_type` ,  `client_name` ,  `logo_uri` ,  `tos_uri` ,  `redirect_uris` ,  `post_logout_redirect_uris` ,  `token_endpoint_auth_method` ,  `token_endpoint_auth_signing_alg` ,  `policy_uri` ,  `jwks_uri` ,  `jwk_encryption_uri` ,  `x509_uri` ,  `x509_encryption_uri` ,  `sector_identifier_uri` ,  `subject_type` ,  `request_object_signing_alg` ,  `userinfo_signed_response_alg` ,  `userinfo_encrypted_response_alg` ,  `userinfo_encrypted_response_enc` ,  `id_token_signed_response_alg` ,  `id_token_encrypted_response_alg` ,  `id_token_encrypted_response_enc` ,  `default_max_age` ,  `require_auth_time` ,  `default_acr_values` ,  `initiate_login_uri` ,  `post_logout_redirect_uri` ,  `request_uris` ,  `grant_types` ,  `response_types`  ) VALUES(  '{$_POST['client_id_issued_at']}' ,  '{$_POST['client_id']}' ,  '{$_POST['client_secret']}' ,  '{$_POST['client_secret_expires_at']}' ,  '{$_POST['registration_access_token']}' ,  '{$_POST['registration_client_uri_path']}' ,  '{$_POST['contacts']}' ,  '{$_POST['application_type']}' ,  '{$_POST['client_name']}' ,  '{$_POST['logo_uri']}' ,  '{$_POST['tos_uri']}' ,  '{$_POST['redirect_uris']}' ,  '{$_POST['post_logout_redirect_uris']}' ,  '{$_POST['token_endpoint_auth_method']}' ,  '{$_POST['token_endpoint_auth_signing_alg']}' ,  '{$_POST['policy_uri']}' ,  '{$_POST['jwks_uri']}' ,  '{$_POST['jwk_encryption_uri']}' ,  '{$_POST['x509_uri']}' ,  '{$_POST['x509_encryption_uri']}' ,  '{$_POST['sector_identifier_uri']}' ,  '{$_POST['subject_type']}' ,  '{$_POST['request_object_signing_alg']}' ,  '{$_POST['userinfo_signed_response_alg']}' ,  '{$_POST['userinfo_encrypted_response_alg']}' ,  '{$_POST['userinfo_encrypted_response_enc']}' ,  '{$_POST['id_token_signed_response_alg']}' ,  '{$_POST['id_token_encrypted_response_alg']}' ,  '{$_POST['id_token_encrypted_response_enc']}' ,  '{$_POST['default_max_age']}' ,  '{$_POST['require_auth_time']}' ,  '{$_POST['default_acr_values']}' ,  '{$_POST['initiate_login_uri']}' ,  '{$_POST['post_logout_redirect_uri']}' ,  '{$_POST['request_uris']}' ,  '{$_POST['grant_types']}' ,  '{$_POST['response_types']}'  ) "; 
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
    
<tr><td>Client Id Issued At:</td><td><input type='text' name='client_id_issued_at'/> </td></tr>
<tr><td>Client Id:</td><td><input type='text' name='client_id'/>  </td></tr>
<tr><td>Client Secret:</td><td><input type='text' name='client_secret'/>  </td></tr>
<tr><td>Client Secret Expires At:</td><td><input type='text' name='client_secret_expires_at'/>  </td></tr>
<tr><td>Registration Access Token:</td><td><input type='text' name='registration_access_token'/>  </td></tr>
<tr><td>Registration Client Uri Path:</td><td><input type='text' name='registration_client_uri_path'/>  </td></tr>
<tr><td>Contacts:</td><td><textarea name='contacts'></textarea>  </td></tr>
<tr><td>Application Type:</td><td><input type='text' name='application_type'/>  </td></tr>
<tr><td>Client Name:</td><td><input type='text' name='client_name'/>  </td></tr>
<tr><td>Logo Uri:</td><td><input type='text' name='logo_uri'/>  </td></tr>
<tr><td>Tos Uri:</td><td><input type='text' name='tos_uri'/>  </td></tr>
<tr><td>Redirect Uris:</td><td><textarea name='redirect_uris'></textarea>  </td></tr>
<tr><td>Post Logout Redirect Uris:</td><td><textarea name='post_logout_redirect_uris'></textarea>  </td></tr>
<tr><td>Token Endpoint Auth Method:</td><td><input type='text' name='token_endpoint_auth_method'/>  </td></tr>
<tr><td>Token Endpoint Auth Signing Alg:</td><td><input type='text' name='token_endpoint_auth_signing_alg'/>  </td></tr>
<tr><td>Policy Uri:</td><td><input type='text' name='policy_uri'/>  </td></tr>
<tr><td>Jwks Uri:</td><td><input type='text' name='jwks_uri'/>  </td></tr>
<tr><td>Jwk Encryption Uri:</td><td><input type='text' name='jwk_encryption_uri'/>  </td></tr>
<tr><td>X509 Uri:</td><td><input type='text' name='x509_uri'/>  </td></tr>
<tr><td>X509 Encryption Uri:</td><td><input type='text' name='x509_encryption_uri'/>  </td></tr>
<tr><td>Sector Identifier Uri:</td><td><input type='text' name='sector_identifier_uri'/>  </td></tr>
<tr><td>Subject Type:</td><td><input type='text' name='subject_type'/>  </td></tr>
<tr><td>Request Object Signing Alg:</td><td><input type='text' name='request_object_signing_alg'/>  </td></tr>
<tr><td>Userinfo Signed Response Alg:</td><td><input type='text' name='userinfo_signed_response_alg'/>  </td></tr>
<tr><td>Userinfo Encrypted Response Alg:</td><td><input type='text' name='userinfo_encrypted_response_alg'/>  </td></tr>
<tr><td>Userinfo Encrypted Response Enc:</td><td><input type='text' name='userinfo_encrypted_response_enc'/>  </td></tr>
<tr><td>Id Token Signed Response Alg:</td><td><input type='text' name='id_token_signed_response_alg'/>  </td></tr>
<tr><td>Id Token Encrypted Response Alg:</td><td><input type='text' name='id_token_encrypted_response_alg'/>  </td></tr>
<tr><td>Id Token Encrypted Response Enc:</td><td><input type='text' name='id_token_encrypted_response_enc'/>  </td></tr>
<tr><td>Default Max Age:</td><td><input type='text' name='default_max_age'/>  </td></tr>
<tr><td>Require Auth Time:</td><td><input type='text' name='require_auth_time'/>  </td></tr>
<tr><td>Default Acr Values:</td><td><input type='text' name='default_acr_values'/>  </td></tr>
<tr><td>Initiate Login Uri:</td><td><input type='text' name='initiate_login_uri'/>  </td></tr>
<tr><td>Post Logout Redirect Uri:</td><td><input type='text' name='post_logout_redirect_uri'/>  </td></tr>
<tr><td>Request Uris:</td><td><textarea name='request_uris'></textarea>  </td></tr>
<tr><td>Grant Types:</td><td><input type='text' name='grant_types'/>  </td></tr>
<tr><td>Response Types:</td><td><input type='text' name='response_types'/>  </td></tr>


</table>
</div>
    <br/><br/>
    <p><input type='submit' value='Add Row' /><input type='hidden' value='1' name='submitted' />

</form>
