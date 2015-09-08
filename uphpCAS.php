<?php
// Thrown when internal error occurs
class JasigException extends Exception {}
// Thrown when CAS server returns authentication error
class JasigAuthException extends JasigException {}

class JasigUser {
	public $user;
	public $attributes = array();
}

class uphpCAS {
	const VERSION = '1.0';
	protected $serverUrl = '';
	protected $serviceUrl;
	protected $sessionName = 'uphpCAS-user';
	protected $method = 'POST';
	protected $caFile = NULL;
	
	function __construct($serverUrl = NULL, $serviceUrl = NULL, $sessionName = NULL) {
		if($serverUrl != NULL) {
			$this->serverUrl = rtrim($serverUrl, '/');
		}
		
		if($serviceUrl != NULL) {
			$this->serviceUrl = $serviceUrl;
		} else {
			$this->serviceUrl = $this->getCurrentUrl();
		}
		
		if($sessionName) {
			$this->sessionName = $sessionName;
		}
		
		if(version_compare(PHP_VERSION, '5.6', '<')) {
			$this->caFile = $this->findCaFile();
		}
	}
	
	public function getCurrentUrl() {
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
		
		if(isset($_GET['ticket'])) {
			$pos = max(
				strrpos($url, '?ticket='),
				strrpos($url, '&ticket=')
			);
			$url = substr($url, 0, $pos);
		}
		
		return $url;
	}
	
	public function getServerUrl() {
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
	
	public function getSessionName() {
		return $this->sessionName;
	}
	public function setSessionName($sessionName) {
		$this->sessionName = $sessionName;
	}
	
	public function getMethod() {
		return $this->method;
	}
	public function setMethod($method) {
		if($method != 'GET' && $method != 'POST') {
			throw new DomainException('Unsupported CAS response'
				.' method: '.$method);
		}
		$this->method = $method;
	}
	
	public function getCaFile() {
		return $this->caFile;
	}
	public function setCaFile($caFile) {
		if(!is_file($caFile)) {
			throw new DomainException('Invalid CA file: '.$caFile);
		}
		$this->caFile = $caFile;
	}
	
	public function loginUrl() {
		return $this->serverUrl.'/login?method='.$this->method
			.'&service='.urlencode($this->serviceUrl);
	}
	
	public function logoutUrl($returnUrl = NULL) {
		return $this->serverUrl.'/logout'
			.($returnUrl ? '?service='.urlencode($returnUrl) : '');
	}
	
	public function logout($returnUrl = NULL) {
		@session_start();
		if($this->isAuthenticated()) {
			unset($_SESSION[$this->sessionName]);
			header('Location: '.$this->logoutUrl($returnUrl));
			die();
		} elseif($returnUrl) {
			header('Location: '.$returnUrl);
			die();
		}
	}
	
	public function isAuthenticated() {
		return isset($_SESSION[$this->sessionName]);
	}
	
	public function authenticate() {
		@session_start();
		if($this->isAuthenticated()) {
			return $_SESSION[$this->sessionName];
		} elseif(isset($_REQUEST['ticket'])) {
			$user = $this->verifyTicket($_REQUEST['ticket']);
			$_SESSION[$this->sessionName] = $user;
			return $user;
		} else {
			header('Location: '.$this->loginUrl());
			die();
		}
	}
	
	protected function findCaFile() {
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
		
		return $cafile;
	}
	
	protected function createStreamContext($hostname) {
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
		
		if($this->caFile) {
			$context['ssl']['cafile'] = $this->caFile;
		}
		
		if(version_compare(PHP_VERSION, '5.6', '<')) {
			$context['ssl']['ciphers'] = 'ECDH:DH:AES:CAMELLIA:!SSLv2:!aNULL'
				.':!eNULL:!EXPORT:!DES:!3DES:!MD5:!RC4:!ADH:!PSK:!SRP';
			$context['ssl']['CN_match'] = $hostname;
		}
		
		return stream_context_create($context);
	}
	
	public function verifyTicket($ticket) {
		$url = parse_url($this->serverUrl);
		$context = $this->createStreamContext($url['host']);
		
		$data = file_get_contents($this->serverUrl
					.'/serviceValidate?service='.urlencode($this->serviceUrl)
					.'&ticket='.urlencode($ticket), FALSE, $context);
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
		} catch(Exception $e) {
			libxml_clear_errors();
			libxml_disable_entity_loader($xmlEntityLoader);
			libxml_use_internal_errors($xmlInternalErrors);
			throw new JasigException('Authentication error: CAS server'
					.' response invalid - parse error', 0, $e);
		}
		libxml_clear_errors();
		libxml_disable_entity_loader($xmlEntityLoader);
		libxml_use_internal_errors($xmlInternalErrors);
		
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
			if(strlen($user) < 1) {
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
		} else {
			throw new JasigException('Authentication error: CAS server'
					.' response invalid - required tag not found');
		}
	}
}
