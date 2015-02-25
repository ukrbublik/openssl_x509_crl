<?php

/**
 * X.509 basic
 *
 */
 
/**
 * X.509
 *
 */
class X509
{
	/** @var array List of certificate revoke reasons */
	protected static $revoke_reasons = array(
		0 => 'unspecified',
		1 => 'keyCompromise',
		2 => 'CACompromise',
		3 => 'affiliationChanged',
		4 => 'superseded',
		5 => 'cessationOfOperation',
		6 => 'certificateHold',
		8 => 'removeFromCRL',
		9 => 'privilegeWithdrawn',
		10 => 'aACompromise'
	);
	/**
	 * Certificate revoke reasons: code -> name
	 *
	 * @param string $s name
	 * @return null|int code
	 */
	public static function getRevokeReasonCodeByName($s) {
		$search_key = array_search($s, self::$revoke_reasons);
		if($search_key === false)
			return null;
		else
			return $search_key;
	}
	/**
	 * Certificate revoke reasons: name -> code
	 *
	 * @param int $c code
	 * @return null|string name
	 */
	public static function getRevokeReasonNameByCode($c) {
		if(array_key_exists($c, self::$revoke_reasons))
			return self::$revoke_reasons[$c];
		else
			return null;
	}
	
	
	/** @var array List of certificate hold instructions */
	protected static $hold_instructions = array(
		0 => 'None',
		1 => 'CallIssuer',
		2 => 'Reject'
	);
	/**
	 * Certificate hold instructions: code -> name
	 *
	 * @param string $s name
	 * @return null|int code
	 */
	public static function getHoldInstructionCodeByName($s) {
		$search_key = array_search($s, self::$hold_instructions);
		if($search_key === false)
			return null;
		else
			return $search_key;
	}
	/**
	 * Certificate hold instructions: name -> code
	 *
	 * @param int $c code
	 * @return null|string name
	 */
	public static function getHoldInstructionNameByCode($s) {
		if(array_key_exists($s, self::$hold_instructions))
			return self::$hold_instructions[$s];
		else
			return null;
	}

	/** @var array List of bits of key usage */
	protected static $key_usages = array(
	  0 => 'digitalSignature',
	  1 => 'nonRepudiation',
	  2 => 'keyEncipherment',
	  3 => 'dataEncipherment',
	  4 => 'keyAgreement',
	  5 => 'keyCertSign',
	  6 => 'cRLSign',
	  7 => 'encipherOnly',
	  8 => 'decipherOnly'
	);
	/**
	 * Get list of bits of key usage
	 *
	 * @return array
	 */
	public static function getKeyUsagesBits() {
		return self::$key_usages;
	}
	
	/** @var array List of bits of NS cerificate types */
	protected static $ns_cert_types = array(
		0 => "client",
		1 => "server",
		2 => "email",
		3 => "objsign",
		4 => null,
		5 => "sslCA",
		6 => "emailCA",
		7 => "objCA",
	);
	/**
	 * Get list of bits of NS cerificate types
	 *
	 * @return array
	 */
	public static function getNsCertTypes() {
		return self::$ns_cert_types;
	}
	
	/** @var array List of bits of revoke reason (for CRL) */
	protected static $revoke_reason_bits = array(
		0 => null,
		1 => 'keyCompromise',
		2 => 'cACompromise',
		3 => 'affiliationChanged',
		4 => 'superseded',
		5 => 'cessationOfOperation',
		6 => 'certificateHold'
	);
	/**
	 * Get list of bits of revoke reason (for CRL)
	 *
	 * @return array
	 */
	public static function getRevokeReasonBits() {
		return self::$revoke_reason_bits;
	}
	
	
	/**
	 * Convert certificate data from PEM format to DER
	 *
	 * @param string $pem data in PEM format
	 * @return false|string data in DER format
	 */
	public static function pem2der($pem) {
	    $matches = array();
	    if (!preg_match('~^-----BEGIN ([A-Z0-9 ]+)-----\s*?([A-Za-z0-9+=/\r\n]+)\s*?-----END \1-----\s*$~D', $pem, $matches))
	        return false;
	    $pem_filtr = str_replace(array("\r", "\n"), array('', ''), $matches[2]);
	    $derData = base64_decode($pem_filtr);
	    return $derData;
	}
	
	/**
	 * Convert certificate data from DER format to PEM
	 *
	 * @param string $der data in DER format
	 * @return false|string data in PEM format
	 */
	public static function der2pem4cert($der) {
	   $der_enc = base64_encode($der);
	   if($der_enc == false)
	   	   return false;
	   $pem = chunk_split($der_enc, 64, "\n");
	   $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
	   return $pem;
	}
	
	/**
	 * Convert CRK data from DER format to PEM
	 *
	 * @param string $der data in DER format
	 * @return false|string data in PEM format
	 */
	public static function der2pem4crl($der) {
	   $der_enc = base64_encode($der);
	   if($der_enc == false)
	   	   return false;
	   $pem = chunk_split($der_enc, 64, "\n");
	   $pem = "-----BEGIN X509 CRL-----\n" . $pem . "-----END X509 CRL-----\n";
	   return $pem;
	}
	
	/**
	 * Check required extensions
	 *
	 */
	public static function checkServer() {
		if(!function_exists('bcadd'))
			throw new Exception("No bcmath extension!");
		if(!function_exists('openssl_pkey_get_details'))
			throw new Exception("No openssl extension!");
		if(!function_exists('date_parse_from_format')) {
			//throw new Exception("PHP 5.3+ is required!");
			
			//@src http://stackoverflow.com/questions/6668223/php-date-parse-from-format-alternative-in-php-5-2
			function date_parse_from_format($format, $date) {
				// reverse engineer date formats
				$keys = array(
					'Y' => array('year', '\d{4}'),              //Année sur 4 chiffres
					'y' => array('year', '\d{2}'),              //Année sur 2 chiffres
					'm' => array('month', '\d{2}'),             //Mois au format numérique, avec zéros initiaux
					'n' => array('month', '\d{1,2}'),           //Mois sans les zéros initiaux
					'M' => array('month', '[A-Z][a-z]{3}'),     //Mois, en trois lettres, en anglais
					'F' => array('month', '[A-Z][a-z]{2,8}'),   //Mois, textuel, version longue; en anglais, comme January ou December
					'd' => array('day', '\d{2}'),               //Jour du mois, sur deux chiffres (avec un zéro initial)
					'j' => array('day', '\d{1,2}'),             //Jour du mois sans les zéros initiaux
					'D' => array('day', '[A-Z][a-z]{2}'),       //Jour de la semaine, en trois lettres (et en anglais)
					'l' => array('day', '[A-Z][a-z]{6,9}'),     //Jour de la semaine, textuel, version longue, en anglais
					'u' => array('hour', '\d{1,6}'),            //Microsecondes
					'h' => array('hour', '\d{2}'),              //Heure, au format 12h, avec les zéros initiaux
					'H' => array('hour', '\d{2}'),              //Heure, au format 24h, avec les zéros initiaux
					'g' => array('hour', '\d{1,2}'),            //Heure, au format 12h, sans les zéros initiaux
					'G' => array('hour', '\d{1,2}'),            //Heure, au format 24h, sans les zéros initiaux
					'i' => array('minute', '\d{2}'),            //Minutes avec les zéros initiaux
					's' => array('second', '\d{2}')             //Secondes, avec zéros initiaux
					//todo: 'O' => ...
				);
				// convert format string to regex
				$regex = '';
				$chars = str_split($format);
				foreach ( $chars AS $n => $char ) {
					$lastChar = isset($chars[$n-1]) ? $chars[$n-1] : '';
					$skipCurrent = '\\' == $lastChar;
					if ( !$skipCurrent && isset($keys[$char]) ) {
						$regex .= '(?P<'.$keys[$char][0].'>'.$keys[$char][1].')';
					}
					else if ( '\\' == $char ) {
						//$regex .= $char;
					}
					else {
						$regex .= preg_quote($char);
					}
				}

				$dt = array();
				$dt['error_count'] = 0;
				// now try to match it
				if( preg_match('#^'.$regex.'$#', $date, $dt) ){
					foreach ( $dt AS $k => $v ){
						if ( is_int($k) ){
							unset($dt[$k]);
						}
					}
					if( !checkdate($dt['month'], $dt['day'], $dt['year']) ){
						$dt['error_count'] = 1;
					}
				}
				else {
					$dt['error_count'] = 1;
				}
				$dt['errors'] = array();
				$dt['fraction'] = '';
				$dt['warning_count'] = 0;
				$dt['warnings'] = array();
				$dt['is_localtime'] = 0;
				$dt['zone_type'] = 0;
				$dt['zone'] = 0;
				$dt['is_dst'] = '';
				return $dt;
			}
		}
	}
}

?>