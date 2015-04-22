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


DROP DATABASE IF EXISTS `phpoidc_01`;
CREATE DATABASE `phpoidc_01`;
USE phpoidc_01;


--
-- Table structure for table `accounts`
--

DROP TABLE IF EXISTS `account`;
CREATE TABLE `account` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `enabled` tinyint(1) DEFAULT '1',
  `login` varchar(255) NOT NULL,
  `crypted_password` varchar(255) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `given_name` varchar(255) DEFAULT NULL,
  `given_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `given_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `family_name` varchar(255) DEFAULT NULL,
  `family_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `family_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `middle_name` varchar(255) DEFAULT NULL,
  `middle_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `middle_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `nickname` varchar(255) DEFAULT NULL,
  `preferred_username` varchar(255) DEFAULT NULL,
  `profile` varchar(255) DEFAULT NULL,
  `picture` varchar(255) DEFAULT NULL,
  `website` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `email_verified` tinyint(1) DEFAULT '0',
  `gender` varchar(255) DEFAULT NULL,
  `birthdate` varchar(255) DEFAULT NULL,
  `zoneinfo` varchar(255) DEFAULT NULL,
  `locale` varchar(255) DEFAULT NULL,
  `phone_number` varchar(255) DEFAULT NULL,
  `phone_number_verified` tinyint(1) DEFAULT '0',
  `address` varchar(255) DEFAULT NULL,
  `updated_at` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`, `login`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



--
-- Table structure for table `clients`
--

DROP TABLE IF EXISTS `client`;
CREATE TABLE `client` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_id_issued_at` int(11) NULL,
  `client_id` varchar(255) NOT NULL,
  `client_secret` varchar(255) DEFAULT NULL,
  `client_secret_expires_at` int(11) DEFAULT NULL,
  `registration_access_token` varchar(255) DEFAULT NULL,
  `registration_client_uri_path` varchar(255) DEFAULT NULL,
  `contacts` text,
  `application_type` varchar(255) DEFAULT NULL,
  `client_name` varchar(255) DEFAULT NULL,
  `logo_uri` varchar(255) DEFAULT NULL,
  `tos_uri` varchar(255) DEFAULT NULL,
  `redirect_uris` text,
  `post_logout_redirect_uris` text,
  `token_endpoint_auth_method` varchar(255) DEFAULT NULL,
  `token_endpoint_auth_signing_alg` varchar(255) DEFAULT NULL,
  `policy_uri` varchar(255) DEFAULT NULL,
  `jwks_uri` varchar(255) DEFAULT NULL,
  `jwk_encryption_uri` varchar(255) DEFAULT NULL,
  `x509_uri` varchar(255) DEFAULT NULL,
  `x509_encryption_uri` varchar(255) DEFAULT NULL,
  `sector_identifier_uri` varchar(255) DEFAULT NULL,
  `subject_type` varchar(255) DEFAULT NULL,
  `request_object_signing_alg` varchar(255) DEFAULT NULL,
  `userinfo_signed_response_alg` varchar(255) DEFAULT NULL,
  `userinfo_encrypted_response_alg` varchar(255) DEFAULT NULL,
  `userinfo_encrypted_response_enc` varchar(255) DEFAULT NULL,
  `id_token_signed_response_alg` varchar(255) DEFAULT NULL,
  `id_token_encrypted_response_alg` varchar(255) DEFAULT NULL,
  `id_token_encrypted_response_enc` varchar(255) DEFAULT NULL,
  `default_max_age` int(11) DEFAULT NULL,
  `require_auth_time` tinyint(1) DEFAULT NULL,
  `default_acr_values` varchar(255) DEFAULT NULL,
  `initiate_login_uri` varchar(255) DEFAULT NULL,
  `post_logout_redirect_uri` varchar(255) DEFAULT NULL,
  `request_uris` text DEFAULT NULL,
  `grant_types` varchar(255) DEFAULT NULL,
  `response_types` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



--
-- Table structure for table `providers`
--

DROP TABLE IF EXISTS `provider`;
CREATE TABLE `provider` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` text NOT NULL,
  `url` varchar(255) NOT NULL,
  `issuer` varchar(255) NOT NULL,
  `client_id` varchar(255) NOT NULL,
  `client_secret` varchar(255) NOT NULL,
  `client_id_issued_at` int(11) DEFAULT NULL,
  `client_secret_expires_at` int(11) DEFAULT NULL,
  `registration_access_token` varchar(255) DEFAULT NULL,
  `registration_client_uri` varchar(255) DEFAULT NULL,
  `authorization_endpoint` varchar(255) DEFAULT NULL,
  `token_endpoint` varchar(255) DEFAULT NULL,
  `userinfo_endpoint` varchar(255) DEFAULT NULL,
  `check_id_endpoint` varchar(255) DEFAULT NULL,
  `check_session_iframe` varchar(255) DEFAULT NULL,
  `end_session_endpoint` varchar(255) DEFAULT NULL,
  `jwks_uri` varchar(255) DEFAULT NULL,
  `jwk_encryption_uri` varchar(255) DEFAULT NULL,
  `x509_uri` varchar(255) DEFAULT NULL,
  `x509_encryption_uri` varchar(255) DEFAULT NULL,
  `registration_endpoint` varchar(255) DEFAULT NULL,
  `scopes_supported` text,
  `response_types_supported` text,
  `grant_types_supported` varchar(255) DEFAULT NULL,
  `acr_values_supported` text,
  `subject_types_supported` varchar(255) DEFAULT NULL,
  `userinfo_signing_alg_values_supported` varchar(255) DEFAULT NULL,
  `userinfo_encryption_alg_values_supported` varchar(255) DEFAULT NULL,
  `userinfo_encryption_enc_values_supported` varchar(255) DEFAULT NULL,
  `id_token_signing_alg_values_supported` varchar(255) DEFAULT NULL,
  `id_token_encryption_alg_values_supported` varchar(255) DEFAULT NULL,
  `id_token_encryption_enc_values_supported` varchar(255) DEFAULT NULL,
  `request_object_signing_alg_values_supported` varchar(255) DEFAULT NULL,
  `request_object_encryption_alg_values_supported` varchar(255) DEFAULT NULL,
  `request_object_encryption_enc_values_supported` varchar(255) DEFAULT NULL,
  `token_endpoint_auth_methods_supported` varchar(255) DEFAULT NULL,
  `token_endpoint_auth_signing_alg_values_supported` varchar(255) DEFAULT NULL,
  `display_values_supported` varchar(255) DEFAULT NULL,
  `claim_types_supported` varchar(255) DEFAULT NULL,
  `claims_supported` text DEFAULT NULL,
  `service_documentation` varchar(255) DEFAULT NULL,
  `claims_locales_supported` varchar(255) DEFAULT NULL,
  `ui_locales_supported` varchar(255) DEFAULT NULL,
  `require_request_uri_registration` tinyint(1) DEFAULT NULL,
  `op_policy_uri` varchar(255) DEFAULT NULL,
  `op_tos_uri` varchar(255) DEFAULT NULL,
  `claims_parameter_supported` tinyint(1) DEFAULT NULL,
  `request_parameter_supported` tinyint(1) DEFAULT NULL,
  `request_uri_parameter_supported` tinyint(1) DEFAULT NULL,

  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;




--
-- Table structure for table `request_files`
--

DROP TABLE IF EXISTS `request_file`;
CREATE TABLE `request_file` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `fileid` varchar(255) NOT NULL,
  `request` text,
  `type` tinyint(1) DEFAULT NULL,
  `jwt` text,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index_request_files_on_fileid` (`fileid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `sites`
--

DROP TABLE IF EXISTS `user_trusted_client`;
CREATE TABLE `user_trusted_client` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `trustedclients_account_id_accounts_id` FOREIGN KEY (`account_id`) REFERENCES `account` (`id`) ON DELETE CASCADE ,
  CONSTRAINT `trustedclients_client_id_clients_id` FOREIGN KEY (`client_id`) REFERENCES `client` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `tokens`
--

DROP TABLE IF EXISTS `token`;

CREATE TABLE `token` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) NOT NULL,
  `token` text NOT NULL,
  `token_type` tinyint(4) DEFAULT '1',
  `client` varchar(255) NOT NULL,
  `details` text,
  `issued_at` datetime NOT NULL,
  `expiration_at` datetime NOT NULL,
  `info` text,
  PRIMARY KEY (`id`),
  KEY `account_id_idx` (`account_id`),
  CONSTRAINT `tokens_account_id_accounts_id` FOREIGN KEY (`account_id`) REFERENCES `account` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



--
-- Insert values into account table
--

INSERT INTO `account` VALUES (
  0,
  1,
  'alice',
  'b6263bb14858294c08e4bdfceba90363e10d72b4',
  'Alice Yamada',
  'ヤマダアリサ',
  '山田亜理紗',
  'Alice',
  'アリサ',
  '亜理紗',
  'Yamada',
  'ヤマダ',
  '山田',
  NULL,
  NULL,
  NULL,
  'Standard Alice Nickname',
  'AlicePreferred',
  'http://www.wonderland.com/alice',
  'smiling_woman.jpg',
  'http://www.wonderland.com',
  'alice@wonderland.com',
  1,
  'female',
  '2000-08-08',
  'America/Los Angeles',
  'en',
  '1-81-234-234234234',
  1,
  '123 wonderland way',
  23453453
),
(0,
 1,
 'bob',
 'cc8684eed2b6544e89242558df73a7208c9391b4',
 'Bob Ikeda',
 'イケダボブ',
 '池田保夫',
 'Bob',
 'ボブ',
 '保夫',
 'Ikeda',
 'イケダ',
 '池田',
 NULL,
 NULL,
 NULL,
 'BobNick',
 'BobPreferred',
 'http://www.underland.com/bob',
 'smiling_woman.jpg',
 'http://www.underland.com',
 'bob@underland.com',
 1,
 'male',
 '2111-11-11',
 'France/Paris',
 'fr',
 '1-81-234-234234234',
 1,
 '456 underland ct.',
 8472378234
);


--
-- Insert values into client table
--

INSERT INTO `client` (`id`, `client_id_issued_at`, `client_id`, `client_secret`, `client_secret_expires_at`, `registration_access_token`, `registration_client_uri_path`, `contacts`, `application_type`, `client_name`, `logo_uri`, `tos_uri`, `redirect_uris`, `post_logout_redirect_uris`, `token_endpoint_auth_method`, `token_endpoint_auth_signing_alg`, `policy_uri`, `jwks_uri`, `jwk_encryption_uri`, `x509_uri`, `x509_encryption_uri`, `sector_identifier_uri`, `subject_type`, `request_object_signing_alg`, `userinfo_signed_response_alg`, `userinfo_encrypted_response_alg`, `userinfo_encrypted_response_enc`, `id_token_signed_response_alg`, `id_token_encrypted_response_alg`, `id_token_encrypted_response_enc`, `default_max_age`, `require_auth_time`, `default_acr_values`, `initiate_login_uri`, `post_logout_redirect_uri`, `request_uris`, `grant_types`, `response_types`) VALUES
(1, 0, 'hello_client', 'hello_secret', 0, '', '', '', '', 'Hello Demo', '', '', 'http://hello/', '', 'client_secret_basic', '', '', 'http://localhost/projects/keystore.jwk', '', '', '', '', 'public', 'RS256', '', '', '', NULL, NULL, NULL, 0, 0, '', '', '', '', 'authorization_code|refresh_token', 'code|token|id_token|code token|code id_token|id_token token|code id_token token'),
(16, 0, 'TIM', 'timsecret', 0, '', '', '', '', 'TIM', '', '', 'http://tim/', '', 'private_key_jwt', '', '', 'http://localhost/projects/keystore.jwk', '', '', '', '', 'public', 'RS256', '', '', '', NULL, NULL, NULL, 0, 0, '', '', '', '', 'authorization_code|refresh_token', 'code|token|id_token|code token|code id_token|id_token token|code id_token token');

