<?php
/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Contributions:
 * Orange Labs: added TIM features, all modifications are prefixed by the tag [TIM]
 *
 */

function handle_openid_config() {
    $endpoint_base =  OP_INDEX_PAGE;

    $discovery = Array(
                        'version' => '3.0',
                        'issuer' => OP_URL,
                        'authorization_endpoint' => $endpoint_base . '/auth',
                        'token_endpoint' => $endpoint_base . '/token',
                        'userinfo_endpoint' => $endpoint_base . '/userinfo',
                        'check_session_iframe' => OP_URL . '/opframe.php',
                        'end_session_endpoint' => $endpoint_base . '/endsession',
//    		            [TIM] added revoke_logout_endpoint to revoke tim app key and logout
    		            'revoke_logout_endpoint' => $endpoint_base . '/logout',
    					'jwks_uri' =>  OP_JWK_URL,
                        'registration_endpoint' => $endpoint_base . '/registration',
                        'scopes_supported' => Array('openid', 'profile', 'email', 'address'),
                        'response_types_supported' => Array('code', 'code token', 'code id_token', 'token', 'token id_token', 'code token id_token', 'id_token'),
                        'grant_types_supported' => Array('authorization_code', 'implicit'),
//                      'acr_values_supported' => Array('http://www.idmanagement.gov/schema/2009/05/icam/openid-trust-level1.pdf'),
                        'acr_values_supported' => Array(),
                        'subject_types_supported' => Array('public', 'pairwise'),

                        'userinfo_signing_alg_values_supported' => Array('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'),
                        'userinfo_encryption_alg_values_supported' => Array('RSA1_5', 'RSA-OAEP'),
                        'userinfo_encryption_enc_values_supported' => Array('A128CBC-HS256', 'A256CBC-HS512', 'A128GCM', 'A256GCM'),

                        'id_token_signing_alg_values_supported' => Array('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'),
                        'id_token_encryption_alg_values_supported' => Array('RSA1_5', 'RSA-OAEP'),
                        'id_token_encryption_enc_values_supported' => Array('A128CBC-HS256', 'A256CBC-HS512', 'A128GCM', 'A256GCM'),

                        'request_object_signing_alg_values_supported' => Array('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'),
                        'request_object_encryption_alg_values_supported' => Array('RSA1_5', 'RSA-OAEP'),
                        'request_object_encryption_enc_values_supported' => Array('A128CBC-HS256', 'A256CBC-HS512', 'A128GCM', 'A256GCM'),

                        'token_endpoint_auth_methods_supported' => Array('client_secret_post', 'client_secret_basic', 'client_secret_jwt', 'private_key_jwt'),
                        'token_endpoint_auth_signing_alg_values_supported' => Array('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'),

                        'display_values_supported' => Array('page'),
                        'claim_types_supported' => Array('normal'),
                        'claims_supported' => Array('name','given_name','family_name','middle_name','nickname','preferred_username','profile','picture','website','email','email_verified','gender','birthdate','zoneinfo','locale','phone_number', 'phone_number_verified','address','updated_at'),
                        'service_documentation' => $endpoint_base . '/servicedocs',

                        'claims_locales_supported' => Array('en-US'),
                        'ui_locales_supported' => Array('en-US'),
                        'require_request_uri_registration' => false,
                        'op_policy_uri' => $endpoint_base . '/op_policy',
                        'op_tos_uri' => $endpoint_base . '/op_tos',

                        'claims_parameter_supported' => true,
                        'request_parameter_supported' => true,
                        'request_uri_parameter_supported' => true
                      );

    header('Content-Type: application/json');
    echo pretty_json(json_encode($discovery));
}
