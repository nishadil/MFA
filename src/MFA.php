<?php

namespace Nishadil\MFA;

use Throwable;
use Exception;

use function ord;
use function sizeof;
use function is_array;
use function random_bytes;
use function function_exists;
use function mcrypt_create_iv;
use function openssl_random_pseudo_bytes;

class MFA{
    

    public static int $mfa_secretCodeLength = 16;
    
    
    function __construct(){
    }




    public static function createSecretCode() : string {
        
        $base32LookupTable = self::base32LookupTable();

        $createRandomBytes = self::createRandomBytes();

        if( $createRandomBytes === null || !is_array($createRandomBytes) || sizeof($createRandomBytes) < 1 ):
            throw new Exception("NIshadil\MFA : Failed to create random bytes");
        endif;

        $secretCode = '';
        for($i = 0; $i < self::$mfa_secretCodeLength; ++$i):
            $secretCode .= $base32LookupTable[ord($createRandomBytes[$i]) & 31];
        endfor;

        return $secretCode;

    }



    public static function getTOTP() : string {

    }






    public static function setSecretCodeLength( int $secretCodeLength = null ) : self {

        if( $secretCodeLength === null || $secretCodeLength<16 || $secretCodeLength>128 ):
            $secretCodeLength = 16;
        endif;

        self::$mfa_secretCodeLength = $secretCodeLength;

        return self::class;
    }



    private static function createRandomBytes() : ?array {
        
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