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

require_once('doctrine_bootstrap.php');


$status_text = null;

$db_name = 'phpoidc_db';
$db_user = 'username';
$db_password = 'password';
$db_host = 'localhost';
$db_port = '3306';
$configFileContents = '';
$link = null;

$show_db_config = true;

if(file_exists('dbconf.php')) {
    require_once('dbconf.php');
    $db_name = DB_DATABASE;
    $db_user = DB_USER;
    $db_password = DB_PASSWORD;
    $db_host = DB_HOST;
    $db_port = DB_PORT;
}

if(isset($_POST['Db'])) {
    require_once('libconfig.php');
    $db =$_POST['Db'];
    $db_name = $db['dbname'];
    $db_user = $db['uname'];
    $db_password = $db['pwd'];
    $db_host = $db['dbhost'];
    $db_port = $db['dbport'];

    $configFileContents = '';

    $show_db_config = false;
    if(!is_writable(OP_DB_CONF_FILE) || !is_writable(RP_DB_CONF_FILE)) {
        if(!is_writable(OP_DB_CONF_FILE))
            $unwriteable_file = OP_DB_CONF_FILE;
        else
            $unwriteable_file = RP_DB_CONF_FILE;
        $status_text = sprintf('Unable to write database configuration to file %s. Make sure the web server process has write permission for that directory.', $unwriteable_file);

        $link = sprintf("<a href='config.php'>Retry</a>");;
    } else {
        $configFileContents = '';
        $status1 = configureDB(DB_CONF_TEMPLATE, OP_DB_CONF_FILE, $db_host, $db_port, $db_name, $db_user,$db_password, $configFileContents);
        if($status === false) {
            $status_text = sprintf('Unable to write database configuration to file %s. Make sure the web server process has write permission for that directory.', OP_DB_CONF_FILE);
        }
        else {
            if($configFileContents) {
                file_put_contents(RP_DB_CONF_FILE, $configFileContents);
                $configFileContents = null;
            }
            require_once('libdb.php');
            require_once('migration.php');

            $dsn = sprintf('%s://%s:%s@%s:%s/%s', 'mysql', $db_user, $db_password, $db_host, $db_port, $db_name);
            try {
                $db_connection = Doctrine_Manager::connection();
                if(!$db_connection->connect())
                    $show_db_config = true;
                else {
                    migrate_db();
                    $status_text = 'Database configuration successful.';
                }
            } catch(Doctrine_Connection_Exception $e) {
                $status_text = "Unable to make connection to database.\n" . $e->getMessage();
                $show_db_config = true;
            }
            catch(Doctrine_Migration_Exception $e) {
                $status_text = "Unable to migrate database.\n" . $e->getMessage();
            }
       }
    }
}


?>

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta name="viewport" content="width=device-width" />
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>phpOidc Setup Configuration File</title>
    <link rel="stylesheet" href="config.css" type="text/css" />
</head>
<body class="phpoidc-core-ui">
<?php if ($status_text) { ?>
    <p><?php echo $status_text; ?></p>
<?php } ?>

<?php if($configFileContents) { ?>
    <textarea cols="98" rows="15" class="code" readonly="readonly">
<?php echo htmlentities($configFileContents, ENT_COMPAT, 'UTF-8'); ?>
    </textarea>
<?php } ?>

<?php if($link) echo $link; ?>


<?php if($show_db_config) { ?>

<form method="post" action="config.php">
    <p>Enter your database connection details.</p>
    <table class="form-table">
        <tr>
            <th scope="row"><label for="dbname">Database Name</label></th>
            <td><input name="Db[dbname]" id="dbname" type="text" size="25" value="<?echo $db_name; ?>" /></td>
            <td>The name of the database you want to store data in.</td>
        </tr>
        <tr>
            <th scope="row"><label for="uname">User Name</label></th>
            <td><input name="Db[uname]" id="uname" type="text" size="25" value="<?echo $db_user; ?>" /></td>
            <td>Your MySQL username</td>
        </tr>
        <tr>
            <th scope="row"><label for="pwd">Password</label></th>
            <td><input name="Db[pwd]" id="pwd" type="text" size="25" value="<?echo $db_password; ?>" /></td>
            <td>&hellip;and your MySQL password.</td>
        </tr>
        <tr>
            <th scope="row"><label for="dbhost">Database Host</label></th>
            <td><input name="Db[dbhost]" id="dbhost" type="text" size="25" value="<?echo $db_host; ?>" /></td>
            <td>The host name or IP address of the MySQL database server.</td>
        </tr>
        <tr>
            <th scope="row"><label for="dbport">Database Host</label></th>
            <td><input name="Db[dbport]" id="dbport" type="text" size="25" value="<?echo $db_port; ?>" /></td>
            <td>The port that your MySQL database server is listening on.</td>
        </tr>
    </table>
    <p class="step"><input name="submit" type="submit" value="Submit" class="button button-large" /></p>
</form>

<?php } ?>
</body>
</html>