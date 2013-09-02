<?php

//####################################################################
//
// File: auth_ticket.inc.php
//
// By:   Luc Germain, STI, Universite de Sherbrooke
// Date: 2004-02-17
//
//#####################################################################
//
//#####################################################################
//
// This file defines functions to generate cookie tickets compatible
// with the "mod_auth_tkt" apache module.
//
//#####################################################################

// Configuration

// Weather we encrypt the data or not
$ENCRYPT_COOKIE = true;

// File name where the secret key is stored
$SECRET_KEY_FILE = "/path/to/file.txt";

// Initial seed for calls to rand
if( !isset($SeedIsDone) ) { 
    srand((double)microtime()*1000000); 
    $SeedIsDone = true; 
}

//---------------------------------------------------------------
// Functions
//---------------------------------------------------------------

//---------------------------------------------------------------
// $result = getSecretKey( );
//---------------------------------------------------------------
//
// Returns a string that contains the secret key used to sign the
// cookie. Read from the secret key file.
//
//---------------------------------------------------------------
function getSecretKey() {
    global $SECRET_KEY_FILE;
    $keyword = "TktAuthSecret";
    $minKeyLength = 10;
    $matches = array();
    $secretKey = "";

    $content = file_get_contents( $SECRET_KEY_FILE );
    if( $content === FALSE ){
        // Cannot read key file
        stopOnError( "F0006" );
    }
    
    if( preg_match( "/^\s*$keyword\s+\"(.*?)\"/m", 
                    $content, $matches ) ) {
        $secretKey = $matches[1];
    }

    if( strlen( $secretKey ) < $minKeyLength ) {
        // Key invalid or not found
        stopOnError( "F0007" );
    }
    
    return( $secretKey );
}

//---------------------------------------------------------------
// $result = stopOnError( $code );
//---------------------------------------------------------------
//
// Display an error code in html and exit
//
//---------------------------------------------------------------
function stopOnError( $code ) {
    echo " <p>The program encountered an unexpected error.</p>
           <p>Error code: $code</p>";
    exit( );
}

//---------------------------------------------------------------
// $result = getTKTHash( $ip, $user, $tokens, $data, $key,
//                       [, $base64 [, $ts]] );
//---------------------------------------------------------------
//
// Returns a string that contains the signed cookie.
//
// The cookie includes the ip address of the user, the user UID, the
// tokens, the user data and a time stamp. The cookie can be
// optionnally base64 encoded. The data is also crypted with the
// encode() function.
//
//---------------------------------------------------------------
function getTKTHash( $ip, $user, $tokens, $data, $key, $base64 = false, $ts = "" ) {

    // set the timestamp to now 
    // unless a time is specified
    if( $ts == "" ) {
        $ts = time();
    }
    //ip2long returns FALSE on an IPv6 address
    $ip_long = ip2long($ip);
    if ( $ip_long !== FALSE)
    {
        $ipts = pack( "NN", $ip_long, $ts );
    } else {
        $ipts = inet_pton($ip) . pack( "N", $ts );       
    }

    // make the cookie signature
    $digest0 = md5( $ipts . $key . $user . "\0" . $tokens . "\0" . $data );
    $digest = md5( $digest0 . $key );

    if( $tokens ){
        $tkt = sprintf( "%s%08x%s!%s!%s", $digest, $ts, 
                        encode( $user, $ts, 0 ),
                        encode( $tokens, $ts, 4 ),
                        encode( $data, $ts, 8 ) );
    } else {
        $tkt = sprintf( "%s%08x%s!%s", $digest, $ts, 
                        encode( $user, $ts, 0 ),
                        encode( $data, $ts, 8 ) );
    }
    if( $base64 ) {
        return( base64_encode( $tkt ) );
    } else {
        return( $tkt );
    }
}

//---------------------------------------------------------------
// $result = encode( $data, $timestamp, $offset );
//---------------------------------------------------------------
//
// Returns a "crypted" version of the data. The length of the data is
// unchanged.
//
// The encryption is deactivated (the function simply returns the
// string unencrypted) if the configuration variable $ENCRYPT_COOKIE
// is not set to TRUE.
//
// The function implements a encryption algorithm that substitutes
// each character for another one using a key to compute the shift
// value. The key is generated from a hash of the timestamp of the
// cookie and the secret key. This key is used from the offset
// specified. This algorithm is reversed in the mod_auth_tkt apache
// module before using the data. This may not be strictly
// cryptographically secure, but should provide sufficient protection
// for the personnal data included in the cookie.
//
//---------------------------------------------------------------
function encode( $data, $timestamp, $offset ) {
    $CHARS_TO_ENCODE = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:";
    $LENGTH = strlen( $CHARS_TO_ENCODE ); 
    $md5key = md5( $timestamp . getSecretKey() );
    $encoded = "";

    global $ENCRYPT_COOKIE;

    // check if encryption is activated
    if( ! $ENCRYPT_COOKIE ) {
        return $data;
    }

    // encode the data one caracter at a time
    for( $i = 0; $i < strlen($data); $i++ ) {

        $pos = strpos( $CHARS_TO_ENCODE, $data{$i} );
        if( $pos === FALSE ) {
            // skip characters that are not in list to encode
            $encoded .= $data{$i};
        } else {
            $newPos = ($pos + (hexdec( $md5key{($offset + $i)%strlen($md5key)} )*7)) % $LENGTH; 
            $encoded .= $CHARS_TO_ENCODE{$newPos};
            // print $data{$i} . " -> $newPos " . $CHARS_TO_ENCODE{$newPos} . "<br>"; 
        }
    }
    // print "<br>md5key = $md5key<br>data = $data<br>encoded = $encoded";
    return $encoded;
}

//---------------------------------------------------------------
// $result = file_get_contents( $filename, $use_include_path = 0 );
//---------------------------------------------------------------
//
// Returns the content of the file in a string, or false if there is
// an error.
//
// This function exists in PHP >= 4.3.0 only
//
//---------------------------------------------------------------
if( !function_exists( 'file_get_contents' ) ) {
    function file_get_contents( $filename, $use_include_path = 0 ) {
        $data = '';
        $file = @fopen( $filename, "rb", $use_include_path );
        if( $file ) {
            while( !feof( $file ) ) {
                $data .= fread( $file, 1024 );
            }
            fclose($file);
        } else {
            /* There was a problem opening the file. */
            return FALSE;
        }
        return $data;
    }
}



?>



