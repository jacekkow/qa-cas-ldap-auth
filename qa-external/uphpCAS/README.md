# uphpCAS

Simple PHP library for CAS authentication

[![Build Status](https://travis-ci.org/jacekkow/uphpCAS.svg?branch=master)](https://travis-ci.org/jacekkow/uphpCAS)

## Introduction

This library intends to be a replacement for overly complex
[phpCAS](https://wiki.jasig.org/display/casc/phpcas) library.

It only supports basic [CAS protocol](http://jasig.github.io/cas/4.0.x/protocol/CAS-Protocol.html),
without proxying capabilities, which is enough for website authentication.

## Usage

### Composer

1. Add jacekkow/uphpcas dependency:
	
	```bash
	composer require jacekkow/uphpcas
	```

1. Include autoloader in your application:
	
	```php
	<?php
	require_once(__DIR__ . '/vendor/autoload.php');
	```

1. See the usage examples below

### Raw usage

1. Download [uphpCAS.php](https://raw.githubusercontent.com/jacekkow/uphpCAS/master/uphpCAS.php)
1. Include it in your application:
	
	```php
	<?php
	require_once(__DIR__ . '/uphpCAS.php');
	```

1. See the usage examples below

## Examples

### Require authentication

To require authentication to access the page:

```php
<?php
require_once('uphpCAS.php');

try {
    $cas = new uphpCAS('https://cas.server.local/cas');
    $user = $cas->authenticate();
    
    echo 'Authenticated as '.$user->user;
} catch(Exception $e) {
    echo 'Jasig authentication failed: '.$e->getMessage();
    die();
}
```

### Login and logout pages

index.php:

```php
<?php
require_once('uphpCAS.php');

$cas = new uphpCAS();
if($cas->isAuthenticated()) {
    $user = $cas->authenticate();
    echo 'Authenticated as '.$user->user;
} else {
    echo 'Not authenticated. <a href="login.php">Log in</a>';
}
```

login.php:

```php
<?php
require_once('uphpCAS.php');

try {
    $cas = new uphpCAS('https://cas.server.local/cas');
    $user = $cas->authenticate();
    
    header('Location: index.php');
} catch(Exception $e) {
    echo 'Jasig authentication failed: '.$e->getMessage();
    die();
}
```

logout.php:

```php
<?php
require_once('uphpCAS.php');

try {
    $cas = new uphpCAS('https://cas.server.local/cas');
    $user = $cas->logout();
} catch(Exception $e) {
    echo 'Jasig authentication failed: '.$e->getMessage();
    die();
}
```

## Common issues

### Invalid redirection from CAS server

By default uphpCAS tries to guess correct URL to pass to CAS server
as a "service" parameter using values from $_SERVER superglobal
(see getCurrentUrl() method). This URL is used by CAS server
to redirect user back to the application after successful CAS login.

If this guess is incorrect, eg. when the server is behind proxy,
you can override it using setServiceUrl() method:

```php
$cas = new uphpCAS('https://cas.server.local/cas');
$cas->setServiceUrl('https://service.local/subpage');
```

or second argument of the constructor:

```php
$cas = new uphpCAS('https://cas.server.local/cas',
	'https://service.local/subpage');
```

### HTTP POST issues

The standard method of passing "ticket" from CAS server to application
is by HTTP GET method. To avoid having additional "ticket" parameter
in the URL on single-page apps, which can expire and cause uphpCAS
to throw exception, this library uses POST method by default.

You can change the method back to HTTP GET with setMethod():

```php
$cas = new uphpCAS('https://cas.server.local/cas');
$cas->setMethod('GET');
```

### CAS over HTTPS

This library enforces CAS certificate validation. The hostname
of the CAS server must match the one in provided SSL certificate.
Also the certificate must be signed by CA included in CA store
(or self-signed - then the certificate itself must be included).
By default it looks for CA store at:

- /etc/ssl/certs/ca-certificates.crt
- /etc/ssl/certs/ca-bundle.crt
- /etc/pki/tls/certs/ca-bundle.crt

You can change path to CA store file using setCaFile() method:

```php
$cas = new uphpCAS('https://cas.server.local/cas');
$cas->setCaFile('./localStore.pem');
```
