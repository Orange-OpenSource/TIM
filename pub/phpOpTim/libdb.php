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

require_once('MDB2.php');
require_once('doctrine_bootstrap.php');
require_once('dbconf.php');


function db_check_credential($username, $password) {

    $q = Doctrine_Query::create()
            ->from('Account a')
            ->where('a.login = ? and crypted_password = ? and enabled = 1', array($username, sha1($password)));
//    printf("%s\n", $q->getSqlQuery());
    return ($q->execute()->count() == 1);
}


function db_get_user($username) {
    
    $q = Doctrine_Query::create()
            ->from('Account a')
            ->where('a.login = ?', array($username));
//    printf("%s\n", $q->getSqlQuery());
    return $q->fetchOne();
}


/////////////////////////////////////////////////////////////////

function db_get_user_objects($username, $object, $sort_field) {

    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->innerJoin('o.Account a')
            ->where('a.login = ?', array($username))
            ->orderBy("o.{$sort_field} ASC");
//    printf("%s\n", $q->getSqlQuery());
    return $q->execute();
}


function db_get_user_object($username, $object, $object_field, $object_value) {

    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->innerJoin('o.Account a')
            ->where("a.login = ? and o.{$object_field} = ?", array($username, $object_value));
//    printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    return ($res && $res->count() == 1) ? $res->getFirst() : false;
}

function db_delete_user_object($username, $object, $object_field, $object_value) {
    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->innerJoin('o.Account a')
            ->where("a.login = ? and o.{$object_field} = ?", array($username, $object_value));
//    printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    if($res && $res->count() == 1)
        $res[0]->delete();
    return true;
}


function db_save_user_object($username, $object, $object_field, $object_value, $object_values) {
    if(!is_array($object_values) || !$object_field || !$object_value)
        return false;
    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->innerJoin('o.Account a')
            ->where("a.login = ? and o.{$object_field} = ?", array($username, $object_value));
    $res = $q->execute();
    $object =  ($res && $res->count() == 1) ? $res[0] : new $object();
    if(!$object->exists()) {
        // Set Account
        $user = db_get_user($username);
        if($user)
            $object['account_id'] = $user['id'];
        else
            return false;
        $object[$object_field] = $object_value;
    }
    $object->merge($object_values);
    $object->save();
    return true;
}



////////////////////////////////////////////////////////
function db_find_token($token) {
    $object = 'Token';
    $object_field = 'token';
    $object_value = $token;
    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->where("o.{$object_field} = ?", array($object_value));
//    printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    return ($res && $res->count()) ? $res->getFirst() : false;
}

function db_find_auth_code($token) {
    $object = 'Token';
    $object_field = 'token';
    $object_value = $token;
    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->where("o.{$object_field} = ? and o.token_type = ?", array($object_value, 0));
//    printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    return ($res && $res->count()) ? $res->getFirst() : false;
}

function db_find_access_token($token) {
    $object = 'Token';
    $object_field = 'token';
    $object_value = $token;
    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->where("o.{$object_field} = ? and o.token_type = ?", array($object_value, 1));
//    printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    return ($res && $res->count()) ? $res->getFirst() : false;
}

// [TIM] find token in the database according to its client_id, username and tim app key kid
function db_find_token_by_clientid_sub_kid($client_id,$sub,$kid) {
    $object = 'Token';
    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->where("o.token_type = ?  and o.info LIKE ?  and o.info LIKE ?  and o.info LIKE ?",
            		array(2,'%"app_id":{"value":"'.$client_id.'"%','%"u":"'.$sub.'"%','%"kid":"'.$kid.'"%' ) );
//	printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    return ($res && $res->count()) ? $res->getFirst() : false;
}

// [TIM] find token in the database according to its client_id, username and tim app key
function db_find_token_by_clientid_sub_tak($client_id,$sub,$tak) {
    $object = 'Token';
    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->where("o.token_type = ?  and o.info LIKE ?  and o.info LIKE ?  and o.info LIKE ?",
            		array(2,'%"app_id":{"value":"'.$client_id.'"%','%"u":"'.$sub.'"%','%"tak":'.$tak.'%' ) );
    //	printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    return ($res && $res->count()) ? $res->getFirst() : false;
}

function db_find_refresh_token($token) {
    $object = 'Token';
    $object_field = 'token';
    $object_value = $token;
    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->where("o.{$object_field} = ? and o.token_type = ?", array($object_value, 2));
//    printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    return ($res && $res->count()) ? $res->getFirst() : false;
}


function db_save_token($token, $token_type, $user, $client, $issued, $expiration, $data=NULL, $details=NULL) {
    if(is_array($data));
        unset($data['name']);
    $token = Array( 'token_type' => $token_type,
                    'client' => $client,
                    'issued_at' => $issued,
                    'expired_at' => $expiration,
                    'details' => $details,
                    'data' => json_encode($data),
                   );
    db_save_user_token($user, $token, $token);
}

function db_get_user_tokens($username) {
    $table = 'Token';
    $sort_field = 'token';
    return db_get_user_objects($username, $table, $sort_field);
}

function db_get_user_token($username, $token) {
    $table = 'Token';
    $object_field = 'token';
    $object_value = $token;
    return db_get_user_object($username, $table, $object_field, $object_value);
}

function db_delete_user_token($username, $token) {
    $table = 'Token';
    $object_field = 'token';
    $object_value = $token;
    return db_delete_user_object($username, $table, $object_field, $object_value);
}

function db_save_user_token($username, $token_name, $token_fields) {
    $table = 'Token';
    $object_field = 'token';
    $object_value = $token_name;
    return db_save_user_object($username, $table, $object_field, $object_value, $token_fields);
}


////////////////////////////////////////////////////////////////////////////
function db_get_user_trusted_clients($username) {
    $object = 'Client';
    $q = Doctrine_Query::create()
        ->select('o.*')
        ->from("$object o")
        ->innerJoin('o.UserTrustedClient otc')
        ->innerJoin('otc.Account a')
        ->where('a.login = ?', array($username));
//    printf("%s\n", $q->getSqlQuery());
    return $q->execute();
}

function db_get_user_trusted_client($username, $client_id) {
    $object = 'Client';
    $q = Doctrine_Query::create()
        ->select('o.*')
        ->from("$object o")
        ->innerJoin('o.UserTrustedClient otc')
        ->innerJoin('otc.Account a')
        ->where('a.login = ? and o.client_id = ?', array($username, $client_id));
//    printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    return ($res && $res->count() == 1) ? $res->getFirst() : false;
}

// [TIM]
function db_get_user_trusted_client_nojoin($username, $client_id) {
    $object = 'UserTrustedClient';
	$user = db_get_user($username);
	if($user)
		$acc_id = $user['id'];
    $q = Doctrine_Query::create()
        ->select('*')
        ->from("$object")
        ->where('account_id = ? and client_id = ?', array($acc_id, $client_id));
//    printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    return ($res && $res->count() == 1) ? $res->getFirst() : false;
}

function db_delete_user_trusted_client($username, $client) {
    $trusted_client = db_get_user_trusted_client_nojoin($username, $client);
    if($trusted_client)
        $trusted_client->delete();
}

function db_save_user_trusted_client($username, $client) {
    $trusted_client = db_get_user_trusted_client($username, $client);
    if(!$trusted_client) {
        $account = db_get_user($username);
        $client = db_get_client($client);
        if($account && $client) {
            $account->TrustedClients[] = $client;
            $account->save();
        }
    }
}

/////////////////////////////////////////////////////////////////

function db_get_accounts() {
    $object = 'Account';
    $sort_field = 'login';
    $q = Doctrine_Query::create()
            ->select('o.*')
            ->from("$object o")
            ->orderBy("o.{$sort_field} ASC");
//    printf("%s\n", $q->getSqlQuery());
    return $q->execute();
}

function db_get_account($username) {
    return db_get_user($username);
}


function db_delete_account($username) {
    $account = db_get_account($username);
    if($account) {
        $account->Tokens->delete();
        $account->ApEndpoints->delete();
        foreach($account->Sites as $site) {
            $site->ReleasePolicies->delete();
        }
        $account->Sites->delete();
        $account->Personas->delete();
        $account->Logs->delete();
        $account->delete();
    }
}


function db_save_account($username, $account_values) {
    if(!is_array($account_values) || !$username)
        return false;
    $account = db_get_account($username);
    if($account) {
        $account->merge($account_values);
        $account->save();
    } else {
        db_save_object('Account', 'login', $username, $account_values);
    }
    return true;
}


///////////////////////////////////////////////////

function db_get_objects($object, $sort_field) {

    $q = Doctrine_Query::create()
//            ->select('o.*')
            ->from("$object o")
            ->orderBy("o.{$sort_field} ASC");
//    printf("%s\n", $q->getSqlQuery());
    return $q->execute();
}

function db_get_object($object, $object_field, $object_value) {

    $q = Doctrine_Query::create()
 //           ->select('o.*')
            ->from("$object o")
            ->where("o.{$object_field} = ?", array($object_value));
//    printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    return ($res && $res->count() == 1) ? $res->getFirst() : false;
}



function db_delete_object($object, $object_field, $object_value) {
    $q = Doctrine_Query::create()
 //           ->select('o.*')
            ->from("$object o")
            ->where("o.{$object_field} = ?", array($object_value));
//    printf("%s\n", $q->getSqlQuery());
    $res = $q->execute();
    if($res && $res->count() == 1)
        $res[0]->delete();
    return true;
}


function db_save_object( $object, $object_field, $object_value, $object_values) {
    if(!is_array($object_values) || !$object_field || !$object_value)
        return false;
    $q = Doctrine_Query::create()
//            ->select('o.*')
            ->from("$object o")
            ->where("o.{$object_field} = ?", array($object_value));
    $res = $q->execute();
    $object =  ($res && $res->count() == 1) ? $res[0] : new $object();
    if(!$object->exists()) {
        $object[$object_field] = $object_value;
    }
    $object->merge($object_values);
    $object->save();
    return true;
}

function db_get_providers() {
    $object = 'Provider';
    $sort_field = 'name';
   return db_get_objects($object, $sort_field);
}


function db_get_provider($name) {
    $object = 'Provider';
    $object_field = 'name';
    $object_value = $name;
    return db_get_object($object, $object_field, $object_value);
}

function db_get_provider_by_url($url) {
    $object = 'Provider';
    $object_field = 'url';
    $object_value = $url;
    return db_get_object($object, $object_field, $object_value);
}

function db_get_provider_by_issuer($url) {
    $object = 'Provider';
    $object_field = 'issuer';
    $object_value = $url;
    return db_get_object($object, $object_field, $object_value);
}


function db_delete_provider($name) {
    $provider = db_get_provider($name);
    if($provider) {
        $provider->delete();
    }
}


function db_save_provider($name, $provider_values) {
    $object = 'Provider';
    $object_field = 'name';
    $object_value = $name;
    $object_values = $provider_values;
    return db_save_object($object, $object_field, $object_value, $object_values);
}


function db_get_clients() {
    $object = 'Client';
    $object_field = 'client_id';
    return db_get_objects($object, $object_field);
}


function db_get_client($client) {

    $object = 'Client';
    $object_field = 'client_id';
    $object_value = $client;
    return db_get_object($object, $object_field, $object_value);
}

function db_get_client_by_registration_token($registration_token) {

    $object = 'Client';
    $object_field = 'registration_access_token';
    $object_value = $registration_token;
    return db_get_object($object, $object_field, $object_value);
}

function db_get_client_by_registration_uri_path($registration_client_uri_path) {

    $object = 'Client';
    $object_field = 'registration_client_uri_path';
    $object_value = $registration_client_uri_path;
    return db_get_object($object, $object_field, $object_value);
}


function db_save_client($name, $client_values) {
    $object = 'Client';
    $object_field = 'client_id';
    $object_value = $name;
    $object_values = $client_values;
    return db_save_object($object, $object_field, $object_value, $object_values);
}


function db_delete_client($name) {
    $client = db_get_client($name);
    if($client) {
        $client->Logs->delete();
        $client->delete();
    }
}

function db_check_client_credential($client_id, $client_secret) {

    $q = Doctrine_Query::create()
            ->from('Client c')
            ->where('client_id = ? and client_secret = ?', array($client_id, $client_secret));
//    printf("%s\n", $q->getSqlQuery());
    return ($q->execute()->count() == 1);
}


function db_get_request_file($fileid) {

    $object = 'RequestFile';
    $object_field = 'fileid';
    $object_value = $fileid;
    return db_get_object($object, $object_field, $object_value);
}

function db_save_request_file($fileid, $request_file_values) {
    $object = 'RequestFile';
    $object_field = 'fileid';
    $object_value = $fileid;
    $object_values = $request_file_values;
    return db_save_object($object, $object_field, $object_value, $object_values);
}
