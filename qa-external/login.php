<?php
define('QA_VERSION', 1);
require_once(dirname(__FILE__).'/handler.php');

try {
	QACASHandler::login();
} catch(Exception $e) {
	echo $e;
}
