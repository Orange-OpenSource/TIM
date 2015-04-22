<?php
header('Content-Type: text/html; charset=utf8');
include(__DIR__ . '/../config.php');
?>
<html>
<head>
    <title></title>
    <link rel="stylesheet" href="../../css/table.css" type="text/css"/>
</head>
<body>
<?php

//$path_info = $_SERVER['PATH_INFO'];
$path_info = isset($_GET['action']) ? $_GET['action'] : 'list';
$file = 'list.php';

switch($path_info) {
    case 'new':
        $file = 'new.php';
        break;

    case 'edit':
        $file = 'edit.php';
        break;

    case 'delete':
        $file = 'delete.php';
        break;

    case 'list':
    default:
        $file = 'list.php';
        break;

}

include($file);
?>

</body>
</html>