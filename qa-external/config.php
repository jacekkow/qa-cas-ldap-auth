<?php
class QACASConfig {
	public static $qa_default_user_level = QA_USER_LEVEL_BASIC;
	public static $qa_session_prefix = 'qa_cas_auth_';
	
	public static $cas_server = 'https://cas.corp/cas';
	
	public static $ldap_server = 'ldaps://ldap.corp';
	public static $ldap_starttls = FALSE;
	public static $ldap_bind_dn = NULL;
	public static $ldap_bind_pass = NULL;
	
	public static $ldap_user_base_dn = 'ou=users,dc=corp';
	public static $ldap_user_base_depth = 'one'; // one or subtree
	public static $ldap_user_filter = '(accountStatus=active)';
	public static $ldap_userid_attr = 'uid';
	public static $ldap_public_username_attr = 'uid';
	public static $ldap_public_display_attr = 'cn';
	public static $ldap_email_attr = 'mail';
	
	public static $ldap_group_base_dn = 'ou=qaSite,ou=groups,dc=corp';
	public static $ldap_group_base_depth = 'one'; // one or subtree
	public static $ldap_group_filter = '';
	public static $ldap_member_group_attr = 'uniqueMember'; // attribute in group's entry
	public static $ldap_member_user_attr = 'dn'; // user's attribute which $ldap_member_group_attr points to
	public static $ldap_level_groups = array(
		// dn -> level
		'cn=SuperUsers,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_SUPER,
		'cn=Admins,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_ADMIN,
		'cn=Moderators,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_MODERATOR,
		'cn=Editors,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_EDITOR,
		'cn=Experts,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_EXPERT,
	);
}
