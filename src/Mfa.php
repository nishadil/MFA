<?php
declare(strict_types=1);

namespace Nishadil\MFA;

use Exception;
use Throwable;

use function chr;
use function ord;
use function floor;
use function time;
use function pack;
use function substr;
use function unpack;
use function str_pad;
use function hash_hmac;
use function array_flip;
use function substr_count;
use function random_bytes;
use function strtoupper;

class Mfa
{
    public static int $mfa_TOTPLength = 6;
    public static int $mfa_secretCodeLength = 16;
    public static int $mfa_secretCodeTime = 30;
    public static string $mfa_algorithm = 'SHA1'; // SHA1 | SHA256 | SHA512
    public static array $mfa_decodeSecretCodeValidValues = [6, 4, 3, 1, 0];

    public static function createSecretCode(): string
    {
        $base32LookupTable = self::base32LookupTable();
        $createRandomBytes = self::createRandomBytes();

        if ($createRandomBytes === null) {
            throw new Exception("Nishadil\\MFA : Failed to create random bytes");
        }

        $secretCode = '';
        for ($i = 0; $i < self::$mfa_secretCodeLength; ++$i) {
            $secretCode .= $base32LookupTable[ord($createRandomBytes[$i]) & 31];
        }

        return $secretCode;
    }

    public static function getTOTP(string $secretCode, int $timeStep = null): string
    {
        $timeStep = self::normalizeTimeStep($timeStep);
        if ($timeStep === null) {
            return '';
        }

        $otp = self::generateOTP($secretCode, (int) floor(time() / $timeStep));
        return $otp ?? '';
    }

    public static function getHOTP(string $secretCode, int $counter): string
    {
        $otp = self::generateOTP($secretCode, $counter);
        return $otp ?? '';
    }

    private static function generateOTP(string $secretCode, int $value): ?string
    {
        $secretCode_decoded = self::decodeSecretCode($secretCode);
        if ($secretCode_decoded === null) {
            return null;
        }

        $counterBytes = pack('N*', 0, $value);
        $hm = hash_hmac(self::$mfa_algorithm, $counterBytes, $secretCode_decoded, true);
        $offset = ord(substr($hm, -1)) & 0x0F;
        $hashpart = substr($hm, $offset, 4);
        $value = unpack('N', $hashpart)[1] & 0x7FFFFFFF;

        return str_pad((string)($value % (10 ** self::$mfa_TOTPLength)), self::$mfa_TOTPLength, '0', STR_PAD_LEFT);
    }

    public static function validateTOTP(string $secretCode, string $userProvided_otp, int $tolerance = 1): bool
    {
        if (!self::isValidOtpFormat($userProvided_otp)) {
            return false;
        }

        $timeStep = self::normalizeTimeStep(null);
        if ($timeStep === null) {
            return false;
        }

        if ($tolerance < 0) {
            return false;
        }

        $currentTimeSlice = (int) floor(time() / $timeStep);

        for ($i = -$tolerance; $i <= $tolerance; $i++) {
            $generatedCode = self::generateOTP($secretCode, $currentTimeSlice + $i);
            if ($generatedCode === null) {
                return false;
            }
            if (hash_equals($generatedCode, $userProvided_otp)) {
                return true;
            }
        }
        return false;
    }

    public static function validateHOTP(string $secretCode, string $userProvided_otp, int $counter): bool
    {
        if (!self::isValidOtpFormat($userProvided_otp)) {
            return false;
        }

        $generatedCode = self::generateOTP($secretCode, $counter);
        if ($generatedCode === null) {
            return false;
        }
        return hash_equals($generatedCode, $userProvided_otp);
    }

    public static function setSecretCodeLength(int $secretCodeLength = 16): void
    {
        if ($secretCodeLength < 16 || $secretCodeLength > 128) {
            $secretCodeLength = 16;
        }
        self::$mfa_secretCodeLength = $secretCodeLength;
    }

    public static function setDigits(int $digits = 6): void
    {
        if ($digits < 6 || $digits > 10) {
            $digits = 6;
        }
        self::$mfa_TOTPLength = $digits;
    }

    public static function setTimeStep(int $timeStep = 30): void
    {
        if ($timeStep <= 0) {
            $timeStep = 30;
        }
        self::$mfa_secretCodeTime = $timeStep;
    }

    public static function setAlgorithm(string $algorithm = 'SHA1'): void
    {
        $algorithm = strtoupper($algorithm);
        if (!in_array($algorithm, ['SHA1', 'SHA256', 'SHA512'], true)) {
            $algorithm = 'SHA1';
        }
        self::$mfa_algorithm = $algorithm;
    }

    public static function generateOtpAuthUri(string $secretCode, string $accountName, string $issuer = 'MyApp', string $type = 'totp', int $counter = 0): string
    {
        $secret = strtoupper($secretCode);
        $algorithm = strtoupper(self::$mfa_algorithm);
        $type = strtolower($type);
        if (!in_array($type, ['totp', 'hotp'], true)) {
            $type = 'totp';
        }

        $baseUri = sprintf(
            "otpauth://%s/%s:%s?secret=%s&issuer=%s&digits=%d&algorithm=%s",
            $type,
            rawurlencode($issuer),
            rawurlencode($accountName),
            $secret,
            rawurlencode($issuer),
            self::$mfa_TOTPLength,
            $algorithm
        );

        if ($type === 'totp') {
            $baseUri .= "&period=" . self::$mfa_secretCodeTime;
        } elseif ($type === 'hotp') {
            $baseUri .= "&counter=" . max(0, $counter);
        }

        return $baseUri;
    }


    public static function generateBackupCodes(int $count = 10, int $length = 8): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = bin2hex(random_bytes((int) ($length / 2)))."-".bin2hex(random_bytes((int) ($length / 2)));
        }
        return $codes;
    }

    private static function createRandomBytes(): ?string
    {
        try {
            return random_bytes(self::$mfa_secretCodeLength);
        } catch (Throwable $th) {
            return null;
        }
    }

    private static function decodeSecretCode(string $secretCode = ''): ?string
    {
        if ($secretCode === null || $secretCode === '') {
            return null;
        }

        $secretCode = strtoupper($secretCode);

        $base32LookupTable = self::base32LookupTable();
        $base32LookupTable_flip = array_flip($base32LookupTable);

        $length = strlen($secretCode);
        $subStrCount = substr_count($secretCode, $base32LookupTable[32]);
        if ($subStrCount > 0) {
            if (!in_array($subStrCount, self::$mfa_decodeSecretCodeValidValues, true)) {
                return null;
            }
            if ($length % 8 !== 0) {
                return null;
            }
            if (substr($secretCode, -$subStrCount) !== str_repeat($base32LookupTable[32], $subStrCount)) {
                return null;
            }
        } else {
            $remainder = $length % 8;
            if (!in_array($remainder, [0, 2, 4, 5, 7], true)) {
                return null;
            }
        }

        $secretCode = str_split(str_replace('=', '', $secretCode));

        $secretCode_decoded = '';
        $buffer = 0;
        $bufferSize = 0;
        for ($i = 0; $i < count($secretCode); ++$i) {
            $char = $secretCode[$i];
            if (!isset($base32LookupTable_flip[$char])) {
                return null;
            }

            $val = $base32LookupTable_flip[$char];
            if ($val === 32) {
                return null;
            }

            $buffer = ($buffer << 5) | $val;
            $bufferSize += 5;

            while ($bufferSize >= 8) {
                $bufferSize -= 8;
                $byte = ($buffer >> $bufferSize) & 0xFF;
                $secretCode_decoded .= chr($byte);
                if ($bufferSize > 0) {
                    $buffer = $buffer & ((1 << $bufferSize) - 1);
                } else {
                    $buffer = 0;
                }
            }
        }

        return $secretCode_decoded;
    }

    private static function normalizeTimeStep(?int $timeStep): ?int
    {
        $timeStep = $timeStep ?? self::$mfa_secretCodeTime;
        if ($timeStep === null || $timeStep <= 0) {
            return null;
        }

        return $timeStep;
    }

    private static function isValidOtpFormat(string $otp): bool
    {
        return $otp !== '' && strlen($otp) === self::$mfa_TOTPLength && ctype_digit($otp);
    }

    private static function base32LookupTable(): array
    {
        return [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
            'Y', 'Z', '2', '3', '4', '5', '6', '7',
            '='
        ];
    }
}
