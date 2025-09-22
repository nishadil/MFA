<?php

require '../vendor/autoload.php';

use Nishadil\Mfa\Mfa;

// $secretCode = Mfa::setSecretCodeLength(128)->createSecretCode();
$secretCode = Mfa::createSecretCode();

echo $secretCode."\n\n";

$secretCode = "3TYBUTVEXBOBXYTJ6L7NZ4HC7QJWAKMY";
$counter = 100;

echo $secretCode."\n\n";

$userProvided_otp = Mfa::getTOTP($secretCode);
echo $userProvided_otp."\n\n";

$userProvided_otp = Mfa::getHOTP($secretCode,(int)$counter);
echo $userProvided_otp."\n\n";

// $userProvided_otp = "163272";
$userProvided_otp = "440791";

// print_r( Mfa::validateTOTP($secretCode, $userProvided_otp) );
print_r( Mfa::validateHOTP($secretCode, $userProvided_otp, $counter) );

echo "\n\n";


// 2. Create otpauth URI for Google Authenticator
$uri = Mfa::generateOtpAuthUri($secretCode, "user@example.com", "NishadilApp");
echo "Scan this URI in Authenticator App : $uri\n";


$backupCodes = Mfa::generateBackupCodes(5);
print_r($backupCodes);
echo "\n\n";
?>