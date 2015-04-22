<?php
// connect to db
require_once "Doctrine.php";
spl_autoload_register(array('Doctrine', 'autoload'));
require_once(__DIR__ . '/../dbconf.php');

$link = mysql_connect(DB_HOST, DB_USER, DB_PASSWORD);
if (!$link) {
    die('Not connected : ' . mysql_error());
}

if (! mysql_select_db(DB_DATABASE) ) {
    die ('Can\'t use foo : ' . mysql_error());
}

