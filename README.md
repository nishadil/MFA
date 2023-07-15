# nishadil\mfa
A php library for Multi-factor authentication (MFA). MFA also known as 2FA or two factor authentication.


# Installation
This library can be installed using `Composer`. To install, please use following command
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