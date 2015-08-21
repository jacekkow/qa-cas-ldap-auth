<?php
require_once(dirname(__FILE__).'/ldap_escape.php');

class LDAPException extends Exception {
	public function __construct($message, $ldap = NULL) {
		if(is_resource($ldap)) {
			$error = ldap_error($ldap);
			if($error) {
				parent::__construct($message.'. '.$error, ldap_errno($ldap));
			} else {
				parent::__construct($message);
			}
		} else {
			parent::__construct($message);
		}
	}
}

class QACASLDAP {
	protected $ldap;
	
	public function __construct() {
		$this->ldap = ldap_connect(QACASConfig::$ldap_server);
		if(!$this->ldap) throw new LDAPException('ldap_connect() failed');
		
		if(!ldap_set_option($this->ldap, LDAP_OPT_PROTOCOL_VERSION, 3)) {
			throw new LDAPException('ldap_set_option(PROTOCOL) failed', $this->ldap);
		}
		if(!ldap_set_option($this->ldap, LDAP_OPT_REFERRALS, false)) {
			throw new LDAPException('ldap_set_option(REFERRALS) failed', $this->ldap);
		}
		
		if(QACASConfig::$ldap_starttls) {
			if(!ldap_start_tls($this->ldap)) {
				throw new LDAPException('ldap_start_tls() failed', $this->ldap);
			}
		}
		
		if(QACASConfig::$ldap_bind_dn) {
			if(!ldap_bind($this->ldap, QACASConfig::$ldap_bind_dn, QACASConfig::$ldap_bind_pass)) {
				throw new LDAPException('ldap_bind() failed', $this->ldap);
			}
		} else {
			if(!ldap_bind($this->ldap, QACASConfig::$ldap_bind_dn, QACASConfig::$ldap_bind_pass)) {
				throw new LDAPException('ldap_bind() failed', $this->ldap);
			}
		}
	}
	
	public function search($base, $depth, $filter, $attrs = array('cn')) {
		$attrs = array_values(array_unique($attrs));
		
		if($depth == 'one') {
			if(($data = ldap_list($this->ldap, $base, $filter, $attrs)) === FALSE) {
				throw new LDAPException('ldap_list() failed', $this->ldap);
			}
		} else {
			if(($data = ldap_search($this->ldap, $base, $filter, $attrs)) === FALSE) {
				throw new LDAPException('ldap_search() failed', $this->ldap);
			}
		}
		
		if(($result = ldap_get_entries($this->ldap, $data)) === FALSE) {
			throw new LDAPException('ldap_get_entries() failed', $this->ldap);
		}
		
		return $result;
	}
	
	public function getAttr($object, $attribute) {
		if(isset($object[$attribute])) {
			if(is_array($object[$attribute])) {
				if(isset($object[$attribute]['count'])
						&& $object[$attribute]['count'] > 0
						&& isset($object[$attribute][0])) {
					return $object[$attribute][0];
				}
			} else {
				return $object[$attribute];
			}
		}
		
		return NULL;
	}
	
	public function getMap($base, $depth, $baseFilter, $keyAttr, $keys, $valAttr) {
		// Generate filter for the search
		$filter = '';
		foreach($keys as $key) {
			$escapedKey = ldap_escape($key, '', LDAP_ESCAPE_FILTER);
			$filter .= '('.$keyAttr.'='.$escapedKey.')';
		}
		$filter = '(&'.$baseFilter.'(|'.$filter.'))';
		
		// Do the search
		if(is_array($valAttr)) {
			$data = $this->search(
				$base, $depth, $filter, array_merge(array($keyAttr), array_values($valAttr))
			);
		} else {
			$data = $this->search(
				$base, $depth, $filter, array($keyAttr, $valAttr)
			);
		}
		
		// Extract $keyAttr and $valAttr from search results
		// to the $result map
		$result = array();
		if(is_array($valAttr)) {
			foreach($data as $userData) {
				$key = $this->getAttr($userData, $keyAttr);
				$result[$key] = array();
				foreach($valAttr as $attrkey => $attr) {
					if(is_int($attrkey)) {
						$result[$key][$attr] = $this->getAttr($userData, $attr);
					} else {
						$result[$key][$attrkey] = $this->getAttr($userData, $attr);
					}
				}
			}
		} else {
			foreach($data as $userData) {
				$key = $this->getAttr($userData, $keyAttr);
				$value = $this->getAttr($userData, $valAttr);
				
				if($key && $value) {
					$result[$key] = $value;
				}
			}
		}
		return $result;
	}
	
	public function getUser($userId) {
		$filter = '(&'.QACASConfig::$ldap_user_filter.'('.QACASConfig::$ldap_userid_attr.'='.ldap_escape($userId, '', LDAP_ESCAPE_FILTER).'))';
		$user = $this->search(
			QACASConfig::$ldap_user_base_dn,
			QACASConfig::$ldap_user_base_depth,
			$filter,
			array(
				QACASConfig::$ldap_userid_attr,
				QACASConfig::$ldap_member_user_attr,
				QACASConfig::$ldap_public_username_attr,
				QACASConfig::$ldap_public_display_attr,
				QACASConfig::$ldap_email_attr
			)
		);
		
		if(isset($user[0])) {
			$user = $user[0];
		} else {
			return NULL;
		}
		
		$userid = $this->getAttr($user, QACASConfig::$ldap_userid_attr);
		if(!$userid) {
			return NULL;
		}
		
		$result = array(
			'userid' => $userid,
			'publicusername' => $userid,
			'display' => $userid,
			'level' => QACASConfig::$qa_default_user_level,
		);
		
		if($value = $this->getAttr($user, QACASConfig::$ldap_public_username_attr)) {
			$result['publicusername'] = $value;
		}
		if($value = $this->getAttr($user, QACASConfig::$ldap_public_display_attr)) {
			$result['display'] = $value;
		}
		if($value = $this->getAttr($user, QACASConfig::$ldap_email_attr)) {
			$result['email'] = $value;
		}
		
		if($value = $this->getAttr($user, QACASConfig::$ldap_member_user_attr)) {
			$filter = '(&'.QACASConfig::$ldap_group_filter.'('.QACASConfig::$ldap_member_group_attr.'='.ldap_escape($value, '', LDAP_ESCAPE_FILTER).'))';
			$groups = $this->search(
				QACASConfig::$ldap_group_base_dn,
				QACASConfig::$ldap_group_base_depth,
				$filter,
				array('dn')
			);
			
			$max_level = -1;
			$i = $groups['count'];
			while(--$i >= 0) {
				$dn = $groups[$i]['dn'];
				if(isset(QACASConfig::$ldap_level_groups[$dn])) {
					$max_level = max($max_level, QACASConfig::$ldap_level_groups[$dn]);
				}
			}
			
			if($max_level != -1) {
				$result['level'] = $max_level;
			}
		}
		
		return $result;
	}
	
	public function getUsers($userIds) {
		return $this->getMap(
			QACASConfig::$ldap_user_base_dn, QACASConfig::$ldap_user_base_depth,
			QACASConfig::$ldap_user_filter, QACASConfig::$ldap_userid_attr, $userIds,
			array(
				'userid' => QACASConfig::$ldap_userid_attr,
				'publicusername' => QACASConfig::$ldap_public_username_attr,
				'display' => QACASConfig::$ldap_public_display_attr,
				'email' => QACASConfig::$ldap_email_attr,
			)
		);
	}
	
	public function getMails($userIds) {
		return $this->getMap(QACASConfig::$ldap_user_base_dn, QACASConfig::$ldap_user_base_depth,
			QACASConfig::$ldap_user_filter, QACASConfig::$ldap_userid_attr, $userIds,
			QACASConfig::$ldap_email_attr);
	}
	
	public function getUsernames($userIds) {
		return $this->getMap(QACASConfig::$ldap_user_base_dn, QACASConfig::$ldap_user_base_depth,
			QACASConfig::$ldap_user_filter, QACASConfig::$ldap_userid_attr, $userIds,
			QACASConfig::$ldap_public_username_attr);
	}
	
	public function getUserIds($usernames) {
		return $this->getMap(QACASConfig::$ldap_user_base_dn, QACASConfig::$ldap_user_base_depth,
			QACASConfig::$ldap_user_filter, QACASConfig::$ldap_public_username_attr, $usernames,
			QACASConfig::$ldap_userid_attr);
	}
}
