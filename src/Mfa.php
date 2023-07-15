<?php

namespace Nishadil\MFA;

use Throwable;
use Exception;

use function chr;
use function ord;
use function pow;
use function floor;
use function time;
use function pack;
use function sizeof;
use function substr;
use function unpack;
use function str_pad;
use function is_array;
use function hash_hmac;
use function array_flip;
use function substr_count;
use function random_bytes;
use function function_exists;
use function mcrypt_create_iv;
use function openssl_random_pseudo_bytes;

class Mfa{
    

    public static int $mfa_TOTPLength = 6;
    public static int $mfa_secretCodeLength = 16;
    public static int $mfa_secretCodeTime = 30;
    public static array $mfa_decodeSecretCodeValidValues = array(6, 4, 3, 1, 0);
    
    
    function __construct(){
    }




    public static function createSecretCode() : string {
        
        $base32LookupTable = self::base32LookupTable();

        $createRandomBytes = self::createRandomBytes();

        if( $createRandomBytes === null ):
            throw new Exception("NIshadil\MFA : Failed to create random bytes");
        endif;

        $secretCode = '';
        for($i = 0; $i < self::$mfa_secretCodeLength; ++$i):
            $secretCode .= $base32LookupTable[ord($createRandomBytes[$i]) & 31];
        endfor;

        return $secretCode;

    }



    public static function getTOTP( string $secretCode ) : string {

        $mfa_time = floor( time() / self::$mfa_secretCodeTime);

        $secretCode_decoded = self::decodeSecretCode( $secretCode );

        if( $secretCode_decoded === null ):
            return '';
        endif;

        // Pack time into binary string
        $mfa_time = chr(0).chr(0).chr(0).chr(0).pack('N*', $mfa_time);
        
        // Hash it with users decoded secret code
        $hm = hash_hmac('SHA1', $mfa_time, $secretCode_decoded, true);
        
        // Use last chr of result as offset
        $offset = ord(substr($hm, -1)) & 0x0F;
        
        // grab 4 bytes of the result
        $hashpart = substr($hm, $offset, 4);

        // Unpak binary value
        $value = unpack('N', $hashpart);
        
        // Only 32 bits
        $value = $value[1] & 0x7FFFFFFF;

        $modulo = pow(10, self::$mfa_TOTPLength);

        return str_pad($value % $modulo, self::$mfa_TOTPLength, '0', STR_PAD_LEFT);

    }






    public static function setSecretCodeLength( int $secretCodeLength = null ) : self {

        if( $secretCodeLength === null || $secretCodeLength<16 || $secretCodeLength>128 ):
            $secretCodeLength = 16;
        endif;

        self::$mfa_secretCodeLength = $secretCodeLength;

        return self::class;
    }



    private static function createRandomBytes() : ?string {
        
        $randomBytes = null;

        if( function_exists('random_bytes') ):
            $randomBytes = random_bytes(self::$mfa_secretCodeLength);
        elseif( function_exists('mcrypt_create_iv') ):
            $randomBytes = mcrypt_create_iv(self::$mfa_secretCodeLength, MCRYPT_DEV_URANDOM);
        elseif( function_exists('openssl_random_pseudo_bytes') ):
            $randomBytes = openssl_random_pseudo_bytes(self::$mfa_secretCodeLength, $orpb);
            $randomBytes = !$orpb ? null : $randomBytes;
        endif;

        return $randomBytes;
    }



    private static function decodeSecretCode( string $secretCode = '' ) : ?string {
        
        if( $secretCode === null || $secretCode === '' ):
            return null;
        endif;

        $base32LookupTable      = self::base32LookupTable();
        $base32LookupTable_flip = array_flip( $base32LookupTable );

        $subStrCount            = substr_count( $secretCode,$base32LookupTable[32] );

        if( !in_array( $subStrCount,self::$mfa_decodeSecretCodeValidValues ) ):
            return null;
        endif;


        for ($i = 0; $i < 4; ++$i) {
            if ($subStrCount == self::$mfa_decodeSecretCodeValidValues[$i] &&
                substr($secretCode, -(self::$mfa_decodeSecretCodeValidValues[$i])) != str_repeat($base32LookupTable[32], self::$mfa_decodeSecretCodeValidValues[$i])) {
                return null;
            }
        }

        $secretCode = str_split( str_replace('=','',$secretCode ) );


        $secretCode_decoded = '';
        for ($i = 0; $i < count($secretCode); $i = $i + 8) {
            $x = '';
            
            if (!in_array($secretCode[$i], $base32LookupTable)):
                return false;
            endif;

            for ($n = 0; $n < 8; ++$n):
                $x .= str_pad(base_convert(@$base32LookupTable_flip[@$secretCode[$i + $n]], 10, 2), 5, '0', STR_PAD_LEFT);
            endfor;
            
            $mfa_eightBits = str_split($x, 8);
            for ($d = 0; $d < count($mfa_eightBits); ++$d):
                $secretCode_decoded .= (($y = chr(base_convert($mfa_eightBits[$d], 2, 10))) || ord($y) == 48) ? $y : '';
            endfor;

        }

        return $secretCode_decoded;

    }



    private static function base32LookupTable(){
        return array(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '=',  // padding char
        );
    }


}

?>