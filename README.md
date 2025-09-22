# nishadil\mfa
A php library for Multi-factor authentication (MFA). MFA also known as 2FA or two factor authentication.

<div align="center">
    <a href="https://github.com/nishadil/MFA/releases/tag/v1.2.0">
        <img src="https://img.shields.io/badge/version-1.2.0-008feb.svg">
        <img src="https://img.shields.io/badge/❤-Nishadil-008feb.svg">
    </a>
</div>

### What is TOTP
TOTP, which stands for Time-based One-Time Password, is a computer algorithm that generates a temporary, unique password for authentication. It's widely used in two-factor authentication (2FA) systems to add an extra layer of security beyond a traditional password. The TOTP algorithm follows an open standard documented in [RFC 6238][RFC6238]. The inputs include a shared secret key and the system time.

### What is HOTP
HOTP stands for HMAC-based One-Time Password and is the original standard that TOTP was based on. Both methods use a secret key as one of the inputs, but while TOTP uses the system time for the other input, HOTP uses a counter, which increments with each new validation. With HOTP, both parties increment the counter and use that to compute the one-time password.
The HOTP standard is documented in [RFC 4226][RFC4226].



# Installation
This library can be installed using [Composer][GETCOMPOSER]. To install, please use following command
```bash
composer require nishadil/mfa
```

# How to use


### Generate Secret Code
To create new secret code for user, call public static mathod `Mfa::createSecretCode();`

```php
<?php

use Nishadil\Mfa\Mfa;

echo Mfa::createSecretCode();

?>
```

output:
```text
F6ZHAZMKSLY7ISFO
```

### Generate long Secret Code

By default, we defined secret code length to *16* char long. You can change it if you need to generate long code. Accepted values should be in integer and within range of 16 to 128.

eg: now we want to generate a 32 char long secret code. `Mfa::setSecretCodeLength(32)->createSecretCode();`

```php
<?php

use Nishadil\Mfa\Mfa;

echo Mfa::setSecretCodeLength(32)->createSecretCode();

?>
```

output:
```text
3TYBUTVEXBOBXYTJ6L7NZ4HC7QJWAKMY
```


### Get TOTP from secret code

TOTP stands for Time-based One-Time Passwords and is a common form of Multi-factor authentication (MFA). To generate your TOTP based on your secret key and time you can call public static mathod `Mfa::getTOTP( string $secretCode );`


```php
<?php

use Nishadil\Mfa\Mfa;

$secretCode = "3TYBUTVEXBOBXYTJ6L7NZ4HC7QJWAKMY";
echo Mfa::getTOTP($secretCode);

?>
```

output:
```text
557480
```


### Validate TOTP

To validate your TOTP based on your secret key and time you can call public static mathod `Mfa::validateTOTP(string $secretCode, string $userProvided_otp);`


```php
<?php

use Nishadil\Mfa\Mfa;

$secretCode = "3TYBUTVEXBOBXYTJ6L7NZ4HC7QJWAKMY";
$userProvided_otp = "440791";

echo Mfa::validateTOTP($secretCode, $userProvided_otp);

?>
```

output:
```text
true
```



### Get HOTP from secret code

HOTP stands for HMAC-based One-Time Password and is the original standard that TOTP was based on. To generate your HOTP based on your secret key and counter value to call public static mathod `Mfa::getHOTP( string $secretCode, int $counter );`


```php
<?php

use Nishadil\Mfa\Mfa;

$secretCode = "3TYBUTVEXBOBXYTJ6L7NZ4HC7QJWAKMY";
$counter = 100;
echo Mfa::getHOTP($secretCode,$counter);

?>
```

output:
```text
440791
```


### Validate HOTP

To validate your HOTP based on your secret key and counter value call public static mathod `Mfa::validateHOTP(string $secretCode, string $userProvided_otp, int $counter);`


```php
<?php

use Nishadil\Mfa\Mfa;

$secretCode = "3TYBUTVEXBOBXYTJ6L7NZ4HC7QJWAKMY";
$counter = 100;
$userProvided_otp = "440791";

echo Mfa::validateHOTP($secretCode, $userProvided_otp, $counter);

?>
```

output:
```text
true
```


### Create otpauth URI for Authenticator Apps
Many authenticator apps, such as Google Authenticator, Authy, and others, support scanning a QR code to quickly set up a new account. The QR code typically contains a special URI, called an `otpauth` URI, which holds all the necessary information for the app to generate one-time passwords.

The `otpauth` URI follows a specific format:
```text
otpauth://[type]/[label]?[parameters]
```

__Generate otpauth URI for TOTP Based method__

```php
<?php

use Nishadil\Mfa\Mfa;

$secretCode = "3TYBUTVEXBOBXYTJ6L7NZ4HC7QJWAKMY";

echo Mfa::generateOtpAuthUri($secretCode, "user@example.com", "NishadilApp");

?>
```

output:
```text
otpauth://totp/NishadilApp:user%40example.com?secret=3TYBUTVEXBOBXYTJ6L7NZ4HC7QJWAKMY&issuer=NishadilApp&digits=6&algorithm=SHA1&period=30
```


__Generate otpauth URI for HOTP Based method__

```php
<?php

use Nishadil\Mfa\Mfa;

$secretCode = "3TYBUTVEXBOBXYTJ6L7NZ4HC7QJWAKMY";
$counter = 100;

echo Mfa::generateOtpAuthUri($secretCode, "user@example.com", "NishadilApp", "hotp", $counter);

?>
```

output:
```text
otpauth://hotp/NishadilApp:user%40example.com?secret=3TYBUTVEXBOBXYTJ6L7NZ4HC7QJWAKMY&issuer=NishadilApp&digits=6&algorithm=SHA1&counter=100
```

# License
This library is licensed for use under the MIT License (MIT)




[RFC6238]: <https://datatracker.ietf.org/doc/html/rfc6238>
[RFC4226]: <https://datatracker.ietf.org/doc/html/rfc4226>
[GETCOMPOSER]: <https://getcomposer.org/>