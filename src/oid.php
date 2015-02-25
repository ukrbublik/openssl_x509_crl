<?php

/**
 * OID
 *
 * @see http://www.oid-info.com
 * @see http://www.alvestrand.no/objectid/
 */

/**
 * OID
 */
class OID
{
	/** @var bool Use online repositories to get human name of OID */
	static public $useOnlineRepos = false;
	
	/**
	 * Get OID of encryption algorithm
	 *
	 * @param int $cipher OPENSSL_KEYTYPE_*
	 * @param int $digest OPENSSL_ALGO_*
	 * @return false|string OID
	 */
	public static function getAlgoOID($cipher, $digest) {
		switch($cipher) {
			case OPENSSL_KEYTYPE_RSA:
				switch($digest) {
					case OPENSSL_ALGO_SHA1:
						return self::getOIDFromName('sha1withRSAEncryption');
					case OPENSSL_ALGO_MD5:
						return self::getOIDFromName('md5withRSAEncryption');
					case OPENSSL_ALGO_MD4:
						return self::getOIDFromName('md4withRSAEncryption');
					case OPENSSL_ALGO_MD2:
						return self::getOIDFromName('md2withRSAEncryption');
					default:
						return false;
				}
			case OPENSSL_KEYTYPE_DSA:
				switch($digest) {
					case OPENSSL_ALGO_SHA1:
						return self::getOIDFromName('dsaWithSHA1Encryption');
					/*case OPENSSL_ALGO_DSS1:
						return self::getOIDFromName('dsaEncryption');*/
					case OPENSSL_ALGO_MD5:
					case OPENSSL_ALGO_MD4:
					case OPENSSL_ALGO_MD2:
						return self::getOIDFromName('dsaEncryption');
					default:
						return false;
				}
			case OPENSSL_KEYTYPE_DH:
				switch($digest) {
					case OPENSSL_ALGO_SHA1:
						return self::getOIDFromName('dhPublicNumber');
					case OPENSSL_ALGO_MD5:
					case OPENSSL_ALGO_MD4:
					case OPENSSL_ALGO_MD2:
						return self::getOIDFromName('dhPublicNumber');
					default:
						return false;
				}
			default:
				return false;
		}
	}
	
	/** @var array Used (not full) list of OIDs and their human names */
	protected static $oids = array(
		// holdInstructions
		"1.2.840.10040.2.1" => "holdInstructionNone",
		"1.2.840.10040.2.2" => "holdInstructionCallIssuer",
		"1.2.840.10040.2.3" => "holdInstructionReject",
		
		// dn
		"2.5.4.5" => "serialNumber",
		"2.5.4.6" => "countryName",
		"2.5.4.8" => "stateOrProvinceName",
		"2.5.4.7" => "localityName",
		"2.5.4.10" => "organizationName",
		"2.5.4.11" => "organizationalUnitName",
		"2.5.4.3" => "commonName",
		"1.2.840.113549.1.9.1" => "emailAddress",
		
		// algorithms
		//hash
		"1.2.840.113549.2.2" => "md2",
		"1.2.840.113549.2.2" => "md4",
		"1.2.840.113549.2.5" => "md5",
		"1.2.840.113549.2.26" => "sha1",
		//dsa
		"1.2.840.10040.4.1" => "dsaEncryption",
		"1.2.840.10040.4.3" => "dsaWithSHA1Encryption",
		//rsa
		"1.2.840.113549.1.1.1" => "rsaEncryption",
		"1.2.840.113549.1.1.2" => "md2withRSAEncryption",
		"1.2.840.113549.1.1.3" => "md4withRSAEncryption",
		"1.2.840.113549.1.1.4" => "md5withRSAEncryption",
		"1.2.840.113549.1.1.5" => "sha1withRSAEncryption",
		//Diffie-Hellman
		"1.2.840.10046.2.1" => "dhPublicNumber",
		
		// extensions
		"2.5.29.14" => "subjectKeyIdentifier",
		"2.5.29.15" => "keyUsage",
		"2.5.29.17" => "subjectAltName",
		"2.5.29.18" => "issuerAltName",
		"2.5.29.37" => "extKeyUsage",
		"2.5.29.19" => "basicConstraints",
		"2.5.29.31" => "cRLDistributionPoints",
		"2.5.29.35" => "authorityKeyIdentifier",
		"2.16.840.1.113730.1.1" => "netscape-cert-type",
		"2.16.840.1.113730.1.4" => "netscape-ca-revocation-url",
		"2.16.840.1.113730.1.13" => "netscape-comment",
		"2.5.29.32" => "certificatePolicies",
		
		// >>>>> pkix (1.3.6.1.5.5.7)
		// private extension ...
		"1.3.6.1.5.5.7.1.1" => "authorityInfoAccess",
		"1.3.6.1.5.5.7.1.11" => "subjectInfoAccess",
		// policy qualifier types
		"1.3.6.1.5.5.7.2.1" => "id-qt-cps",
		"1.3.6.1.5.5.7.2.2" => "id-qt-unotice",
		"1.3.6.1.5.5.7.2.3" => "id-qt-textnotice",
		// ext key usages
		"1.3.6.1.5.5.7.3.1" => "serverAuthentication",
		"1.3.6.1.5.5.7.3.2" => "clientAuthentication",
		"1.3.6.1.5.5.7.3.3" => "codeSigning",
		"1.3.6.1.5.5.7.3.4" => "emailProtection",
		"1.3.6.1.5.5.7.3.5" => "ipsecEndSystem",
  		"1.3.6.1.5.5.7.3.6" => "ipsecTunnel",
  		"1.3.6.1.5.5.7.3.7" => "ipsecUser",
  		"1.3.6.1.5.5.7.3.8" => "timeStamping",
  	 	"1.3.6.1.5.5.7.3.9.1" => "ocspSigning-basic",
  	 	"1.3.6.1.5.5.7.3.9.2" => "ocspSigning-nonce",
  	 	"1.3.6.1.5.5.7.3.9.3" => "ocspSigning-crl",
  	 	"1.3.6.1.5.5.7.3.9.4" => "ocspSigning-responce",
  	 	"1.3.6.1.5.5.7.3.9.5" => "ocspSigning-nocheck",
  	 	"1.3.6.1.5.5.7.3.9.6" => "ocspSigning-archive-cutoff",
  	 	"1.3.6.1.5.5.7.3.9.7" => "ocspSigning-service-locator",
  	 	"1.3.6.1.5.5.7.3.10" => "dvcs",
  	 	"1.3.6.1.5.5.7.3.11" => "sbgpCertAAServerAuth",
  	 	"1.3.6.1.5.5.7.3.13" => "id-kp-eapOverPPP",
  	 	"1.3.6.1.5.5.7.3.14" => "id-kp-eapOverLAN",
  	 	"1.3.6.1.5.5.7.3.15" => "id-kp-scvpServer",
  	 	"1.3.6.1.5.5.7.3.16" => "id-kp-scvpClient",
  	 	"1.3.6.1.5.5.7.3.17" => "id-kp-ipsecIKE",
  	 	//
  	 	"1.3.6.1.5.5.7.48.1" => "ocsp",
  	 	"1.3.6.1.5.5.7.48.2" => "caIssuers",
		// <<<<< pkix (1.3.6.1.5.5.7)
		
		// CRL
		"2.5.29.20" => "cRLNumber",
		"2.5.29.21" => "cRLReason",
		"2.5.29.23" => "instructionCode",
		"2.5.29.24" => "invalidityDate",			
	);
	
	/**
	 * Get OID from human name
	 *
	 * @param string $name OID name
	 * @return null|string OID
	 */
	public static function getOIDFromName($name) {
		if(in_array($name, self::$oids))
			return array_search($name, OID::$oids);
		else
			return null;
	}
	
	/**
	 * Convert OID to human name
	 * Returns OID if can't be converted to human name
	 *
	 * @param string $oid OID
	 * @return string OID name
	 */
	public static function getNameFromOID($oid) {
		if(array_key_exists($oid, self::$oids)) {
			return self::$oids[$oid];
		} else {
			if(self::$useOnlineRepos == false) {
				return $oid;
			} else {
				$n = null;
				$n1 = self::getNameFromOID_Online1($oid);
				if($n1)
					$n = $n1;
				else {
					$n2 = self::getNameFromOID_Online2($oid);
					if($n2)
						$n = $n2;
				}
				if($n) {
					/**
					 * @todo cache?
					 */
					return $n;
				} else {
					return $oid;
				}
			}
		}
	}
	
	/**
	 * Convert OID to human name using http://www.alvestrand.no/objectid/ repository
	 * @see OID::getNameFromOID()
	 *
	 * @param string $oid OID
	 * @return false|string OID name
	 */
	protected static function getNameFromOID_Online1($oid) {
		$html_oid_info = file_get_contents("http://www.alvestrand.no/objectid/" . $oid . ".html");
		if(!$html_oid_info)
			return false;
		
		$expr = "| <\s*title\s*> \s* .*? " . str_replace(".", "\\.", $oid) . " \s* - \s* (.*?) \s* <\s*/\s*title\s*> | six";
		$pockets = null;
		if(preg_match($expr, $html_oid_info, $pockets)) {
			$oid_descr = $pockets[1];
			return $oid_descr;
		} else
			return false;
	}
	
	/**
	 * Convert OID to human name using http://www.oid-info.com/ repository
	 * @see OID::getNameFromOID()
	 *
	 * @param string $oid OID
	 * @return false|string OID name
	 */
	protected static function getNameFromOID_Online2($oid) {
		$html_oid_info = file_get_contents("http://www.oid-info.com/get/" . $oid);
		if(!$html_oid_info)
			return false;
		
		$expr = "# <\s*tt\s*> \s* (.*?) \s* <\s*/\s*tt\s*> # six";
		$pockets = null;
		if(preg_match($expr, $html_oid_info, $pockets)) {
			$oid_descr_full = $pockets[1];
			$expr = "#^ \s* (.*?) \s* (?: [(] (\d+) [)] ) .*?  $# six";
			if(preg_match($expr, $oid_descr_full, $pockets))
				return $pockets[1];
			else
				return $oid_descr_full;
		} else
			return false;
	}
}

?>