# nishadil\mfa
A php library for Multi-factor authentication (MFA).


# Installation
This library can be installed using `Composer`. To install, please use following command
```bash
composer require nishadil/uuid
```

# How to use


### Generate Secret Code
To create new secret code for user, call static mathod Mfa::createSecretCode()

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

eg: now we want to generate a 32 char long secret code.

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

# License
This library is licensed for use under the MIT License (MIT)