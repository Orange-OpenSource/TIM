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


define("LOGFILE", dirname($_SERVER['SCRIPT_FILENAME']) . '/app.log');
define("LOGLEVEL", 'DEBUG');

/*
* Specifies the OP's server name/IP address. By default, it uses what the client uses
*/
if (!defined('OP_SERVER_NAME'))
    define('OP_SERVER_NAME', $_SERVER['SERVER_NAME']);

if (!defined('RP_SERVER_NAME'))
    define('RP_SERVER_NAME', $_SERVER['SERVER_NAME']);

/*
* Specifies the OP's protocol
*/
define("OP_PROTOCOL", 'https://');

/*
* Specifies the OP's protocol port 
* Should use ':port_num' format, e.g. :80
*/
define("OP_PORT", '');

/*
* Specifies the OP's PATH
* 
*/
define("OP_PATH", '/' . basename(dirname($_SERVER['SCRIPT_FILENAME'])));


/*
* Specifies the OP's URL
* 
*/
define("OP_URL", OP_PROTOCOL . OP_SERVER_NAME . OP_PORT . OP_PATH);

/*
* Specifies the RP's protocol 
*/
define("RP_PROTOCOL", 'https://');

/*
* Specifies the RP's protocol port 
* Should use ':port_num' format e.g. :80
*/
define("RP_PORT", '');

/*
* Specifies the RP's PATH
* 
*/
define("RP_PATH", '/' . basename(dirname($_SERVER['SCRIPT_FILENAME'])));

/*
* Specifies the RP's URL
* 
*/
define("RP_URL", RP_PROTOCOL . RP_SERVER_NAME . RP_PORT . RP_PATH);


/**
* path to the OP's private key
*/
define("OP_PKEY", dirname($_SERVER['SCRIPT_FILENAME']) . "/op.key");

/**
* OP's pass phrase for the private key file 
*/
define("OP_PKEY_PASSPHRASE","");

/**
* URL to OP's public JWK
*/
define("OP_JWK_URL", OP_URL . '/op.jwk');

/**
* URL to OP's public JWK for encryption
*/
define("OP_ENC_JWK_URL", OP_URL . '/op.jwk');

/**
* OP's Signature Kid
*/
define("OP_SIG_KID", 'PHPOP-00');

/**
* OP's Encryption Kid
*/
define("OP_ENC_KID", 'PHPOP-00');

/**
* path to the RP's private key
*/
define("RP_PKEY", dirname($_SERVER['SCRIPT_FILENAME']) . "/rp/rp.key");

/**
* RP's pass phrase for the private key file 
*/
define("RP_PKEY_PASSPHRASE","");

/**
* URL to RP's public JWK
*/
define("RP_JWK_URL", RP_URL . '/rp/rp.jwk');

/**
* URL to OP's public JWK for encryption
*/
define("RP_ENC_JWK_URL", RP_URL . '/rp/rp.jwk');

/**
* RP's Signature Kid
*/
define("RP_SIG_KID", 'PHPRP-00');

/**
* RP's Encryption Kid
*/
define("RP_ENC_KID", 'PHPRP-00');

/**
* OP endpoints and metadata
*
*/
define('OP_INDEX_PAGE', OP_URL . '/index.php');
define('OP_AUTH_EP', OP_INDEX_PAGE . '/auth');
define('OP_TOKEN_EP', OP_INDEX_PAGE . '/token');
define('OP_USERINFO_EP', OP_INDEX_PAGE . '/userinfo');
define('OP_CHECKSESSION_EP', OP_INDEX_PAGE . '/checksession');
define('OP_SESSIONINFO_EP', OP_INDEX_PAGE . '/sessioninfo');


/**
* RP endpoints and Metadata
*
*/
define('RP_INDEX_PAGE', RP_URL . '/index.php');
define('RP_REDIRECT_URI', RP_INDEX_PAGE . '/callback');
define('RP_AUTHCHECK_REDIRECT_URI', RP_URL . '/authcheck.php/authcheckcb');
define('RP_POST_LOGOUT_REDIRECT_URI', RP_INDEX_PAGE . '/logoutcb');
define('RP_CLIENT_ID', RP_URL . '/');


?>