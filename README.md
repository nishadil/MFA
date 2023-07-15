# nishadil\mfa
A php library for Multi-factor authentication (MFA). MFA also known as 2FA or two factor authentication.


### What is TOTP
The TOTP algorithm follows an open standard documented in [RFC 6238][RFC6238]. The inputs include a shared secret key and the system time.

### What is HOTP
HOTP stands for HMAC-based One-Time Password and is the original standard that TOTP was based on. Both methods use a secret key as one of the inputs, but while TOTP uses the system time for the other input, HOTP uses a counter, which increments with each new validation. With HOTP, both parties increment the counter and use that to compute the one-time password.
The HOTP standard is documented in [RFC 4226][RFC4226].



# Installation
This library can be installed using [Composer][GETCOMPOSER]. To install, please use following command
```bash
composer require nishadil/uuid
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

# License
This library is licensed for use under the MIT License (MIT)




[RFC6238]: <https://datatracker.ietf.org/doc/html/rfc6238>
[RFC4226]: <https://datatracker.ietf.org/doc/html/rfc4226>
[GETCOMPOSER]: <https://getcomposer.org/>