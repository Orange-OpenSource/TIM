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




define('OP_DB_CONF_FILE',                   __DIR__ . '/dbconf.php');
define('RP_DB_CONF_FILE',                   dirname(__DIR__)  . '/phpRp/dbconf.php');
define('DB_CONF_TEMPLATE',               __DIR__ . '/dbconf.php.sample');

function configureDB($template, $configFile, $host, $port, $db, $user, $password, &$replacedText = null) {
    $config = file_get_contents($template);
    if(!is_null($replacedText))
        $replacedText = '';
    if(isset($config)) {
        $pattern = array(
            '/MYSQL_HOST/',
            '/MYSQL_PORT/',
            '/MYSQL_DATABASE/',
            '/MYSQL_USER/',
            '/MYSQL_PASSWORD/',
            '/MYSQL_HOST/'
        );

        $replacement = array(
            $host,
            $port,
            $db,
            $user,
            $password
        );

        $config = preg_replace($pattern, $replacement, $config);
        if(!is_null($replacedText))
            $replacedText = $config;
        return file_put_contents($configFile, $config);
    }
    return false;
}


function checkDbConf() {
    if(!file_exists(OP_DB_CONF_FILE))
        return true;
    else
        return false;
}


function checkDbConnection()
{
    require_once('libdb.php');
    try {
        $db_connection = Doctrine_Manager::connection();
        if(!$db_connection->connect())
            die(1);
    }
    catch(Doctrine_Connection_Exception $e) {
        die(1);
    }
}

// run from commandline
if(isset($argv) && isset($argv[0]) && (basename($argv[0]) == basename(__FILE__))) {
    if($argc == 6) {
        list($executable, $db_host, $db_port, $db_name, $db_user, $db_password) = $argv;

        configureDB(DB_CONF_TEMPLATE, OP_DB_CONF_FILE, $db_host, $db_port, $db_name, $db_user, $db_password);
        configureDB(DB_CONF_TEMPLATE, RP_DB_CONF_FILE, $db_host, $db_port, $db_name, $db_user, $db_password);
        if(file_exists(OP_DB_CONF_FILE)) {
            require_once('migration.php');
            migrate_db();
        }
    } elseif($argc == 2) {
        list($executable, $command) = $argv;
        switch($command) {
            case 'checkdbconnection' :
                checkDbConnection();
                break;
            default:
        }
    }
}