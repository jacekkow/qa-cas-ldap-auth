# Questions2Answer - CAS + LDAP authentication

This script integrates [Questions2Answer system](http://www.question2answer.org)
with CAS authentication using [uphpCAS library](https://github.com/jacekkow/uphpCAS)
and authorization using data from LDAP server.

## Installation

1. Download [qa-cas-ldap-auth-master.zip](https://github.com/jacekkow/qa-cas-ldap-auth/archive/master.zip)
1. Extract it.
1. Configure module (`qa-external/config.php`). Options are described in `Configuration` section.
1. Copy qa-external directory to the location you installed Questions2Answer to.
1. Uncomment line:
	
	```
	define('QA_EXTERNAL_USERS', true);
	```
	
	in  `qa-config.php`.
1. Follow Questions2Answer installation guide.

## General information

CAS server returns user ID. This ID is used as `userid` in Questions2Answer system.

Additional information, such as e-mail address and username are retrieved from LDAP directory.

## Configuration

This module is configured through `qa-external/config.php` file.

Available options:

### General options

#### $qa_default_user_level

Default permission level for authenticated user. Used when no other permission level
was configured in LDAP directory.

Must be one of the constants:

* `QA_USER_LEVEL_BASIC`
* `QA_USER_LEVEL_APPROVED`
* `QA_USER_LEVEL_EXPERT`
* `QA_USER_LEVEL_EDITOR`
* `QA_USER_LEVEL_MODERATOR`
* `QA_USER_LEVEL_ADMIN`
* `QA_USER_LEVEL_SUPER`

#### $qa_session_prefix

Prefix used to distinguish this Questions2Answer from others under the same domain.
This prefix is used to prefix names of entries in `$_SESSION` array.

If only one instance of Questions2Answer system is installed under one session scope
(see [PHP Session Configuration](http://php.net/manual/en/session.configuration.php)
for more information on session cookies) or all instances use the same set of
users & privileges, no modification is necessary.

### CAS

#### $cas_server

URL of a CAS server, without trailing slash, eg. `https://cas.corp/cas`

`/login` or `/logout` with appropriate parameters will be appended to this value.

### LDAP - general

#### $ldap_server

LDAP server address, eg. `ldap://ldap.corp` or `ldaps://ldap.corp`

Will be passed as-is to [ldap_connect()](http://php.net/manual/en/function.ldap-connect.php)

#### $ldap_starttls

Whather to use STARTTLS encryption for LDAP connection.

Set to `FALSE` if you use LDAPS.

Must be `TRUE` or `FALSE`.

#### $ldap_bind_dn

Connect to LDAP (bind) as this user. Set to `NULL` to do an anonymous bind.

#### $ldap_bind_pass

Password for user specified in `$ldap_bind_dn`

### LDAP - users

#### $ldap_user_base_dn

DN to search users under, eg. `ou=users,dc=corp`

#### $ldap_user_base_depth

How deep to search under `$ldap_user_base_dn`

Possible values are:

* `one` - search the base DN only (one level),
* `subtree` - search whole subtree (all levels).

#### $ldap_user_filter

Filter to apply when searching for users, eg. `(accountStatus=active)`. Single key-value pair
must be enclosed in parenthesis.

This value will be AND-ed with the search filter.

#### $ldap_userid_attr

Name of the attribute in the user's LDAP entry, containing `userid` as returned
by the CAS server, eg. `uid`.

This ID is used internally by Questions2Answer in various DB tables and is not displayed.

#### $ldap_public_username_attr

Name of the attribute in the user's LDAP entry, containing username which will be used publicly
instead of the `userid`. Values must be unique and map one-to-one to `userid`.

If unsure, set to the same value as `$ldap_userid_attr`, eg. `uid`

#### $ldap_public_display_attr

Name of the attribute in the user's LDAP entry, containing which will be displayed instead of
the `username` - for example this may contain user's full name - `cn`

Links to the user profiles will look like this:

```
<a href="/profile/{username}">{display}</a>
```

If unsure, set to the same value as `$ldap_userid_attr`, eg. `uid`

#### $ldap_email_attr

Name of the attribute in the user's LDAP entry, containing user's mail address.
When multiple values are provided by the LDAP server - first one is used.

### LDAP - groups

#### $ldap_group_base_dn

DN to search groups under, eg. `ou=groups,dc=corp`

#### $ldap_group_base_depth

How deep to search under `$ldap_group_base_dn`

Possible values are:

* `one` - search the base DN only (one level),
* `subtree` - search whole subtree (all levels).

#### $ldap_group_filter

Filter to apply when searching for groups, eg. `(objectClass=groupOfUniqueNames)`.
Single key-value pair must be enclosed in parenthesis.

This value will be AND-ed with the search filter.

#### $ldap_member_group_attr

Name of the attribute in the group's LDAP entry, containing reference to the user.

#### $ldap_member_user_attr

Name of the attribute in the users's LDAP entry, which is referenced by attribute
configure id `$ldap_member_group_attr`.

#### $ldap_level_groups

Mapping of the group DNs to permission levels - eg.:

```
'cn=SuperUsers,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_SUPER,
'cn=Admins,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_ADMIN,
'cn=Moderators,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_MODERATOR,
'cn=Editors,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_EDITOR,
'cn=Experts,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_EXPERT,
```

When user is in multiple groups, the highest permission level will be applied.

## LDAP configuration examples

### Example 1

User entries look like this:

```
dn: uid=u1001,ou=users,dc=corp
objectClass: inetOrgPerson
objectClass: posixAccount
cn: John Smith
mail: john.smith@mail.corp
uid: jsmith
uidNumber: 1001
(...)
```

Group entries look like this:

```
dn: cn=Admins,ou=qaSite,ou=groups,dc=corp
objectClass: groupOfUniqueNames
objectClass: top
cn: Admins
uniqueMember: uid=jsmith,ou=users,dc=corp
```

Configuration 1:

```
	public static $ldap_user_base_dn = 'ou=users,dc=corp';
	public static $ldap_user_base_depth = 'one'; // one or subtree
	public static $ldap_user_filter = '(objectClass=posixAccount)';
	public static $ldap_userid_attr = 'uidNumber';
	public static $ldap_public_username_attr = 'uid';
	public static $ldap_public_display_attr = 'cn';
	public static $ldap_email_attr = 'mail';

	public static $ldap_group_base_dn = 'ou=qaSite,ou=groups,dc=corp';
	public static $ldap_group_base_depth = 'one'; // one or subtree
	public static $ldap_group_filter = '(objectClass=groupOfUniqueNames)';
	public static $ldap_member_group_attr = 'uniqueMember';
	public static $ldap_member_user_attr = 'dn';
	public static $ldap_level_groups = array(
		// dn -> level
		'cn=Admins,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_ADMIN,
	);
```

* uidNumber (eg. 1001) will be used to identify users internally,
* uid (eg. jsmith) will be used as a username (in URLs),
* cn (eg. John Smith) will be displayed instead of a username.

Configuration 2:

```
	public static $ldap_user_base_dn = 'ou=users,dc=corp';
	public static $ldap_user_base_depth = 'one'; // one or subtree
	public static $ldap_user_filter = '(objectClass=posixAccount)';
	public static $ldap_userid_attr = 'uid';
	public static $ldap_public_username_attr = 'uid';
	public static $ldap_public_display_attr = 'uid';
	public static $ldap_email_attr = 'mail';

	public static $ldap_group_base_dn = 'ou=qaSite,ou=groups,dc=corp';
	public static $ldap_group_base_depth = 'one'; // one or subtree
	public static $ldap_group_filter = '(objectClass=groupOfUniqueNames)';
	public static $ldap_member_group_attr = 'uniqueMember';
	public static $ldap_member_user_attr = 'dn';
	public static $ldap_level_groups = array(
		// dn -> level
		'cn=Admins,ou=qaSite,ou=groups,dc=corp' => QA_USER_LEVEL_ADMIN,
	);
```

* uid (eg. jsmith) will be used to identify users internally,
* uid (eg. jsmith) will be used as a username (in URLs),
* uid (eg. jsmith) will be displayed instead of a username.
