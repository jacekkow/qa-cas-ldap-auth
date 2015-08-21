<?php
if (!defined('QA_VERSION')) {
	header('Location: ../');
	exit;
}

require_once(dirname(__FILE__).'/uphpCAS/uphpCAS.php');
@session_start();

require_once(dirname(__FILE__).'/../qa-include/qa-base.php');
require_once(dirname(__FILE__).'/../qa-include/app/users.php');
require_once(dirname(__FILE__).'/config.php');
require_once(dirname(__FILE__).'/ldap.php');

class QACASHandler {
	protected static $cas = NULL;
	protected static $ldap = NULL;
	
	protected static function initCas() {
		if(self::$cas == NULL) {
			self::$cas = new uphpCAS(QACASConfig::$cas_server);
		}
	}
	
	protected static function initLdap() {
		if(self::$ldap == NULL) {
			self::$ldap = new QACASLDAP();
		}
	}
	
	public static function getUrls($relative_url_prefix, $redirect_back_to_url) {
		$_SESSION[QACASConfig::$qa_session_prefix.'redirect_url'] = $redirect_back_to_url;
		
		return array(
			'login' => rtrim($relative_url_prefix, '/').'/qa-external/login.php',
			'register' => NULL,
			'logout' => rtrim($relative_url_prefix, '/').'/qa-external/logout.php',
		);
	}
	
	protected static function redirect() {
		$url = '../';
		if(isset($_SESSION[QACASConfig::$qa_session_prefix.'redirect_url'])) {
			$url .= ltrim($_SESSION[QACASConfig::$qa_session_prefix.'redirect_url'], '/');
			unset($_SESSION[QACASConfig::$qa_session_prefix.'redirect_url']);
		}
		
		header('Location: '.$url);
		die();
	}
	
	public static function login() {
		if(!self::isAuthenticated()) {
			self::initCas();
			$user = self::$cas->authenticate();
			
			self::initLdap();
			$userData = self::$ldap->getUser($user->user);
			
			if($userData) {
				$_SESSION[QACASConfig::$qa_session_prefix.'user'] = $userData;
			} else {
				throw new Exception('User data is empty!');
			}
		}
		
		if(!self::isAuthenticated()) {
			throw new Exception('Authentication failed!');
		}
		
		self::redirect();
	}
	
	public static function logout() {
		if(self::isAuthenticated()) {
			unset($_SESSION[QACASConfig::$qa_session_prefix.'user']);
			
			self::initCas();
			self::$cas->logout(self::$cas->getServiceUrl());
		}
		
		self::redirect();
	}
	
	public static function isAuthenticated() {
		return isset($_SESSION[QACASConfig::$qa_session_prefix.'user']);
	}
	
	public static function getUser() {
		return self::isAuthenticated() ? $_SESSION[QACASConfig::$qa_session_prefix.'user'] : NULL;
	}
	
	public static function getUsers($userIds) {
		self::initLdap();
		return self::$ldap->getUsers($userIds);
	}
	
	public static function getUserIds($usernames) {
		self::initLdap();
		return self::$ldap->getUserIds($usernames);
	}
	
	public static function getUsernames($userIds) {
		self::initLdap();
		return self::$ldap->getUsernames($userIds);
	}
	
	public static function getEmail($userId) {
		self::initLdap();
		$mails = self::$ldap->getMails(array($userId));
		if(isset($mails[$userId])) {
			return $mails[$userId];
		}
		return NULL;
	}
}
