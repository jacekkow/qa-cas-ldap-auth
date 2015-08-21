<?php
// Thrown when internal error occurs
class JasigException extends Exception {}
// Thrown when CAS server return authentication error
class JasigAuthException extends JasigException {}

class JasigUser {
	public $user;
	public $attributes = array();
}

class uphpCAS {
	const VERSION = '1.0';
	protected $serverUrl = '';
	protected $serviceUrl;
	
	function __construct($serverUrl = NULL, $serviceUrl = NULL) {
		if($serverUrl != NULL) {
			$this->serverUrl = rtrim($serverUrl, '/');
		}
		
		if($serviceUrl != NULL) {
			$this->serviceUrl = $serviceUrl;
		} else {
			$url = 'http://';
			$port = 0;
			if(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') {
				$url = 'https://';
				if(isset($_SERVER['SERVER_PORT'])
						&& $_SERVER['SERVER_PORT'] != '443') {
					$port = $_SERVER['SERVER_PORT'];
				}
			} elseif(isset($_SERVER['SERVER_PORT'])
					&& $_SERVER['SERVER_PORT'] != '80') {
				$port = $_SERVER['SERVER_PORT'];
			}
			
			$url .= $_SERVER['SERVER_NAME'];
			
			if($port != 0) {
				$url .= ':'.$port;
			}
			$url .= $_SERVER['REQUEST_URI'];
			
			$this->serviceUrl = $url;
		}
	}
	
	public function getServerUrl($serverUrl) {
		return $this->serverUrl;
	}
	public function setServerUrl($serverUrl) {
		$this->serverUrl = $serverUrl;
	}
	
	public function getServiceUrl() {
		return $this->serviceUrl;
	}
	public function setServiceUrl($serviceUrl) {
		$this->serviceUrl = $serviceUrl;
	}
	
	public function loginUrl() {
		return $this->serverUrl.'/login?method=POST&service='.urlencode($this->serviceUrl);
	}
	
	public function logoutUrl($returnUrl = NULL) {
		return $this->serverUrl.'/logout'.($returnUrl ? '?service='.urlencode($returnUrl) : '');
	}
	
	public function logout() {
		session_start();
		if(isset($_SESSION['uphpCAS-user'])) {
			unset($_SESSION['uphpCAS-user']);
		}
		header('Location: '.$this->logoutUrl());
		die();
	}
	
	public function isAuthenticated() {
		return isset($_SESSION['uphpCAS-user']);
	}
	
	public function authenticate() {
		session_start();
		if($this->isAuthenticated()) {
			return $_SESSION['uphpCAS-user'];
		} elseif(isset($_REQUEST['ticket'])) {
			$user = $this->verifyTicket($_REQUEST['ticket']);
			$_SESSION['uphpCAS-user'] = $user;
			return $user;
		} else {
			header('Location: '.$this->loginUrl());
			die();
		}
	}
	
	public function verifyTicket($ticket) {
		$context = array(
			'http' => array(
				'method' => 'GET',
				'user_agent' => 'uphpCAS/'.self::VERSION,
				'max_redirects' => 3,
			),
			'ssl' => array(
				'verify_peer' => TRUE,
				'verify_peer_name' => TRUE,
				'verify_depth' => 5,
				'allow_self_signed' => FALSE,
				'disable_compression' => TRUE,
			),
		);
		
		if(version_compare(PHP_VERSION, '5.6', '<')) {
			$cafiles = array(
				'/etc/ssl/certs/ca-certificates.crt',
				'/etc/ssl/certs/ca-bundle.crt',
				'/etc/pki/tls/certs/ca-bundle.crt',
			);
			$cafile = NULL;
			foreach($cafiles as $file) {
				if(is_file($file)) {
					$cafile = $file;
					break;
				}
			}
			
			$url = parse_url($this->serverUrl);
			$context['ssl']['cafile'] = $cafile;
			$context['ssl']['ciphers'] = 'ECDH:DH:AES:CAMELLIA:!SSLv2:!aNULL'
					.':!eNULL:!EXPORT:!DES:!3DES:!MD5:!RC4:!ADH:!PSK:!SRP';
			$context['ssl']['CN_match'] = $url['host'];
		}
		
		$data = file_get_contents($this->serverUrl
					.'/serviceValidate?service='.urlencode($this->serviceUrl)
					.'&ticket='.urlencode($ticket),
				FALSE, stream_context_create($context));
		if($data === FALSE) {
			throw new JasigException('Authentication error: CAS server is unavailable');
		}
		
		$xmlEntityLoader = libxml_disable_entity_loader(TRUE);
		$xmlInternalErrors = libxml_use_internal_errors(TRUE);
		try {
			$xml = new DOMDocument();
			$xml->loadXML($data);
			
			foreach(libxml_get_errors() as $error) {
				$e = new ErrorException($error->message, $error->code, 1,
						$error->file, $error->line);
				switch ($error->level) {
					case LIBXML_ERR_ERROR:
					case LIBXML_ERR_FATAL:
						throw new Exception('Fatal error during XML parsing',
								0, $e);
						break;
				}
			}
		}
		catch(Exception $e) {
			throw new JasigException('Authentication error: CAS server'
					.' response invalid - parse error', 0, $e);
		} finally {
			libxml_clear_errors();
			libxml_disable_entity_loader($xmlEntityLoader);
			libxml_use_internal_errors($xmlInternalErrors);
		}
		
		$failure = $xml->getElementsByTagName('authenticationFailure');
		$success = $xml->getElementsByTagName('authenticationSuccess');
		
		if($failure->length > 0) {
			$failure = $failure->item(0);
			if(!($failure instanceof DOMElement)) {
				throw new JasigException('Authentication error: CAS server'
						.' response invalid - authenticationFailure');
			}
			throw new JasigAuthException('Authentication error: '
					.$failure->textContent);
		} elseif($success->length > 0) {
			$success = $success->item(0);
			if(!($success instanceof DOMElement)) {
				throw new JasigException('Authentication error: CAS server'
						.' response invalid - authenticationSuccess');
			}
			
			$user = $success->getElementsByTagName('user');
			if($user->length == 0) {
				throw new JasigException('Authentication error: CAS server'
						.' response invalid - user');
			}
			
			$user = trim($user->item(0)->textContent);
			if(strlen($user)<1) {
				throw new JasigException('Authentication error: CAS server'
						.' response invalid - user value');
			}
			
			$jusr = new JasigUser();
			$jusr->user = $user;
			
			$attrs = $success->getElementsByTagName('attributes');
			if($attrs->length > 0) {
				$attrs = $attrs->item(0);
				foreach($attrs->childNodes as $node) {
					$jusr->attributes[$node->localName] = $node->textContent;
				}
			}
			
			return $jusr;
		}
		else
		{
			throw new JasigException('Authentication error: CAS server'
					.' response invalid - required tag not found');
		}
	}
}
