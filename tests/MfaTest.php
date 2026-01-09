<?php
declare(strict_types=1);

namespace Nishadil\Mfa\Tests;

use Nishadil\Mfa\Mfa;
use PHPUnit\Framework\TestCase;

final class MfaTest extends TestCase
{
    public function testBase32EncodeKnownVector(): void
    {
        $secret = '12345678901234567890';

        self::assertSame(
            'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
            $this->base32Encode($secret)
        );
    }

    public function testHotpRfc4226Vectors(): void
    {
        Mfa::setDigits(6);
        Mfa::setAlgorithm('SHA1');

        $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
        $expected = [
            0 => '755224',
            1 => '287082',
            2 => '359152',
            3 => '969429',
            4 => '338314',
            5 => '254676',
            6 => '287922',
            7 => '162583',
            8 => '399871',
            9 => '520489',
        ];

        foreach ($expected as $counter => $otp) {
            self::assertSame($otp, Mfa::getHOTP($secret, $counter));
        }
    }

    public function testTotpRfc6238Vectors(): void
    {
        $timestamps = [
            59 => [
                'SHA1' => '94287082',
                'SHA256' => '46119246',
                'SHA512' => '90693936',
            ],
            1111111109 => [
                'SHA1' => '07081804',
                'SHA256' => '68084774',
                'SHA512' => '25091201',
            ],
            1111111111 => [
                'SHA1' => '14050471',
                'SHA256' => '67062674',
                'SHA512' => '99943326',
            ],
            1234567890 => [
                'SHA1' => '89005924',
                'SHA256' => '91819424',
                'SHA512' => '93441116',
            ],
            2000000000 => [
                'SHA1' => '69279037',
                'SHA256' => '90698825',
                'SHA512' => '38618901',
            ],
            20000000000 => [
                'SHA1' => '65353130',
                'SHA256' => '77737706',
                'SHA512' => '47863826',
            ],
        ];

        $secrets = [
            'SHA1' => $this->base32Encode('12345678901234567890'),
            'SHA256' => $this->base32Encode('12345678901234567890123456789012'),
            'SHA512' => $this->base32Encode('1234567890123456789012345678901234567890123456789012345678901234'),
        ];

        Mfa::setDigits(8);

        foreach ($timestamps as $timestamp => $expectedByAlgorithm) {
            $counter = (int) floor($timestamp / 30);
            foreach ($expectedByAlgorithm as $algorithm => $expected) {
                Mfa::setAlgorithm($algorithm);
                self::assertSame($expected, Mfa::getHOTP($secrets[$algorithm], $counter));
            }
        }
    }

    public function testOtpAuthUriNormalizesType(): void
    {
        Mfa::setDigits(6);
        Mfa::setAlgorithm('SHA1');

        $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

        $totpUri = Mfa::generateOtpAuthUri($secret, 'user@example.com', 'Example', 'TOTP');
        self::assertStringContainsString('otpauth://totp/', $totpUri);
        self::assertStringContainsString('period=', $totpUri);

        $hotpUri = Mfa::generateOtpAuthUri($secret, 'user@example.com', 'Example', 'HOTP', 5);
        self::assertStringContainsString('otpauth://hotp/', $hotpUri);
        self::assertStringContainsString('counter=5', $hotpUri);
    }

    public function testSetTimeStepUpdatesPeriod(): void
    {
        Mfa::setTimeStep(45);

        $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
        $uri = Mfa::generateOtpAuthUri($secret, 'user@example.com', 'Example', 'totp');

        self::assertStringContainsString('period=45', $uri);

        Mfa::setTimeStep(30);
    }

    public function testInvalidInputsDoNotValidate(): void
    {
        Mfa::setDigits(6);
        Mfa::setAlgorithm('SHA1');

        self::assertFalse(Mfa::validateHOTP('ABC0', '000000', 0));
        self::assertFalse(Mfa::validateTOTP('ABC0', '000000'));
        self::assertFalse(Mfa::validateTOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '12ab'));
        self::assertFalse(Mfa::validateTOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '12345'));
    }

    private function base32Encode(string $input): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $binary = '';
        $length = strlen($input);

        for ($i = 0; $i < $length; $i++) {
            $binary .= str_pad(decbin(ord($input[$i])), 8, '0', STR_PAD_LEFT);
        }

        $chunks = str_split($binary, 5);
        $encoded = '';

        foreach ($chunks as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $encoded .= $alphabet[bindec($chunk)];
        }

        $padding = (8 - (strlen($encoded) % 8)) % 8;
        if ($padding > 0) {
            $encoded .= str_repeat('=', $padding);
        }

        return $encoded;
    }
}
