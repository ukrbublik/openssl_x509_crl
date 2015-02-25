<?php

/**
 * X.509 CRL creator
 *
 * @see https://www.ietf.org/rfc/rfc2459.txt
 */

require_once("asn1.php");
require_once("oid.php");
require_once("x509.php");
require_once("x509_cert.php");

/**
 * X.509 CRL
 */
class X509_CRL
{
	/**
	 * Generates and signs CRL from provided data
	 * Returns in DER format
	 *
	 * @param array $ci data for CRL creation. <br>
	 * Format: array(<br>
	 *   'no' => number of CRL,<br>
	 *   'version' => CRL format version, 1 or 2,<br>
	 *   'days' => CRL validity in days from date of creation,<br>
	 *   'alg' => OPENSSL_ALGO_*,<br>
	 *   'revoked' => array( array( //list of revoked certificates<br>
	 *     'serial' => S/N of revoked cert,<br>
	 *     'rev_date' => date of revokation, timestamp,<br>
	 *     'reason' => code of revokation reason, see X509::getRevokeReasonCodeByName(),<br>
	 *     'compr_date' => date when certifacate became compromised, timestamp,<br>
	 *     'hold_instr' => code of hold instruction, see X509::getHoldInstructionCodeByName(),<br>
	 *   ), ... )<br>
	 * )
	 * @param resource $ca_pkey key pair for CA root certificate, got from openssl_pkey_get_private()
	 * @param string $ca_cert CA root certificate data in DER format
	 * @return string CRL in DER format
	 */
	static function create($ci, $ca_pkey, $ca_cert) {
		$ca_decoded = X509_CERT::decode($ca_cert);
		
		//CRL version
		$crl_version = ((isset($ci['version']) && ($ci['version'] == 2 || $ci['version'] == 1)) ? $ci['version'] : 2);
		
		//Algorithm
		$algs_cipher = array( OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_DSA, OPENSSL_KEYTYPE_DH, OPENSSL_KEYTYPE_EC );
		$algs_hash = array( /*OPENSSL_ALGO_DSS1, */OPENSSL_ALGO_SHA1, OPENSSL_ALGO_MD5, OPENSSL_ALGO_MD4 );
		if(defined('OPENSSL_ALGO_MD2'))
			$algs_hash[] = OPENSSL_ALGO_MD2;
		
		$ca_pkey_details = openssl_pkey_get_details($ca_pkey);
		if($ca_pkey_details === false)
			return false;
		$ca_pkey_type = $ca_pkey_details['type'];
		if($ca_pkey_type == OPENSSL_KEYTYPE_EC || $ca_pkey_type == -1)
			return false;
		if(!in_array($ca_pkey_type, $algs_cipher))
			return false;
		
		if(isset($ci['alg']) && !in_array($ci['alg'], $algs_hash))
			return false;
		$crl_hash_alg = (isset($ci['alg']) ? $ci['alg'] : OPENSSL_ALGO_SHA1);		
		
		$sign_alg_oid = OID::getAlgoOID($ca_pkey_type, $crl_hash_alg);
		if($sign_alg_oid === false)
			return false;
		
		//Create CRL stricture
		$crl = new ASN1_SEQUENCE;
		$crl->content['tbsCertList'] = new ASN1_SEQUENCE;
		$tbsCertList = & $crl->content['tbsCertList'];
		
		if($crl_version == 2) {
			$tbsCertList->content['version'] = new ASN1_INT( $crl_version - 1 );
		}
		
		$tbsCertList->content['signature'] = new ASN1_SEQUENCE;
		$tbsCertList->content['signature']->content['algorithm'] = new ASN1_OID( $sign_alg_oid );
		$tbsCertList->content['signature']->content['parameters'] = new ASN1_NULL;
		$tbsCertList->content['issuer'] = X509_CERT::getExtVal_Subject($ca_decoded);
		$tbsCertList->content['thisUpdate'] = new ASN1_UTCTIME( time() );
		if(function_exists('add_date'))
			$nextUpdateTs = add_date(time(), 0, 0, 0, $ci['days']);
		else
			$nextUpdateTs = time() + $ci['days'] * 24*60*60;
		$tbsCertList->content['nextUpdate'] = new ASN1_UTCTIME( $nextUpdateTs );
		
		//Revoked certs list
		if(isset($ci['revoked']) && is_array($ci['revoked']) && !empty($ci['revoked'])) {
			$tbsCertList->content['revokedCertificates'] = new ASN1_SEQUENCE;
			$revokedCerts = & $tbsCertList->content['revokedCertificates'];
			for($i = 0 ; $i < count($ci['revoked']) ; $i++) {
				$ci_rev = & $ci['revoked'][$i];
				$revokedCerts->content[$i] = new ASN1_SEQUENCE;
				$revCert = & $revokedCerts->content[$i];
				$revCert->content['userCertificate'] = new ASN1_INT( $ci_rev['serial'] );
				
				if(!is_null( $ci_rev['rev_date'] )) {
					$revCert->content['revocationDate'] = new ASN1_UTCTIME( $ci_rev['rev_date'] );
				}
				
				// Revo Extensions
				if($crl_version == 2 && !is_null($ci_rev['reason'])) {
					$revCert->content['crlEntryExtensions'] = new ASN1_SEQUENCE;
					$crlExts = & $revCert->content['crlEntryExtensions'];
					
					$crlExts->content['reasonCode'] = new ASN1_SEQUENCE;
					$reasonCode = & $crlExts->content['reasonCode'];
					$reasonCode->content['OID'] = new ASN1_OID(OID::getOIDFromName("cRLReason"));
					$reasonCode->content['VAL'] = new ASN1_OCTETSTRING(false);
					$reasonCode->content['VAL']->content[0] = new ASN1_ENUM( $ci_rev['reason'] );
					
					if( $ci_rev['reason'] == X509::getRevokeReasonCodeByName('keyCompromise') && !is_null( $ci_rev['compr_date'] ) ) {
						$crlExts->content['invalidityDate'] = new ASN1_SEQUENCE;
						$invalidityDate = & $crlExts->content['invalidityDate'];
						$invalidityDate->content['OID'] = new ASN1_OID(OID::getOIDFromName("invalidityDate"));
						$invalidityDate->content['VAL'] = new ASN1_OCTETSTRING(false);
						$invalidityDate->content['VAL']->content[0] = new ASN1_GENERALTIME( $ci_rev['compr_date'] );			
					}
					
					if( $ci_rev['reason'] == X509::getRevokeReasonCodeByName('certificateHold') && !is_null( $ci_rev['hold_instr'] ) ) {
						$crlExts->content['holdInstructionCode'] = new ASN1_SEQUENCE;
						$holdInstructionCode = & $crlExts->content['holdInstructionCode'];
						$holdInstructionCode->content['OID'] = new ASN1_OID(OID::getOIDFromName("instructionCode"));
						$holdInstructionCode->content['VAL'] = new ASN1_OCTETSTRING(false);
						$holdInstructionCode->content['VAL']->content[0] = new ASN1_OID( OID::getOIDFromName( X509::getHoldInstructionNameByCode($ci_rev['hold_instr']) ) );
					}
				}
			}
		}

		//CRL Extensions
		if($crl_version == 2) {
			$tbsCertList->content['crlExtensions'] = new ASN1_SEQUENCE;
			$crlExts = & $tbsCertList->content['crlExtensions'];
			$crlExts->setType(0, true, ASN1_CLASSTYPE_CONTEXT);
			$crlExts->content[0] = new ASN1_SEQUENCE;
			
			$crlExts->content[0]->content['authorityKeyIdentifier'] = new ASN1_SEQUENCE;
			$authKeyId = & $crlExts->content[0]->content['authorityKeyIdentifier'];
			$authKeyId->content['OID'] = new ASN1_OID(OID::getOIDFromName("authorityKeyIdentifier"));
			$authKeyId->content['VAL'] = new ASN1_OCTETSTRING(false);
			$authKeyId->content['VAL']->content[0] = X509_CERT::getExtVal_SubjectKeyIdentifier($ca_decoded);
			
			if(isset($ci['no']) && is_numeric($ci['no'])) {
				$crlExts->content[0]->content['cRLNumber'] = new ASN1_SEQUENCE;
				$cRLNumber = & $crlExts->content[0]->content['cRLNumber'];
				$cRLNumber->content['OID'] = new ASN1_OID(OID::getOIDFromName("cRLNumber"));
				$cRLNumber->content['VAL'] = new ASN1_OCTETSTRING(false);
				$cRLNumber->content['VAL']->content[0] = new ASN1_INT($ci['no']);
			}
		}
		
		//Sign CRL info
		$crl_info = $tbsCertList->encode();
		$crl_sig = "";
		$crl_sign_result = openssl_sign( $crl_info, $crl_sig, $ca_pkey, $crl_hash_alg );
		if(!$crl_sign_result)
			return false;
		
		//Add sign to CRL structure
		$crl->content['signatureAlgorithm'] = new ASN1_SEQUENCE;
		$signAlgo = & $crl->content['signatureAlgorithm'];
		$signAlgo->content['algorithm'] = new ASN1_OID( $sign_alg_oid );
		$signAlgo->content['parameters'] = new ASN1_NULL;
		$crl->content['signature'] = new ASN1_BITSTRING($crl_sig);
		
		//Encode CRL content to DER format
		$crl_encoded = $crl->encode();
		return $crl_encoded;
	}
}


/**
 * Generates and signs CRL from provided data
 * Returns in DER format
 *
 * @see X509_CRL::create()
 */
function openssl_x509_gencrl($ci, $ca_pkey, $ca_data) {
	return X509_CRL::create($ci, $ca_pkey, $ca_data);
}


?>