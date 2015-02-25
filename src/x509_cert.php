<?php

/**
 * X.509 certificate parser
 *
 * @see https://www.ietf.org/rfc/rfc2459.txt
 */

require_once("asn1.php");
require_once("oid.php");
require_once("x509.php");

/**
 * X.509 certificate
 */
class X509_CERT
{
	/**
	 * Decode certificate data in DER format
	 *
	 * @param string $crt_data_der certificate data in DER format
	 * @return ASN1_SEQUENCE root of decoded data
	 */
	public static function decode(&$crt_data_der) {
		$cert = new ASN1_SEQUENCE;
		$cert->decode($crt_data_der, 0, strlen($crt_data_der));
		return $cert->content[0];
	}
	
	/**
	 * Get subject name from decoded certificate data
	 *
	 * @param ASN1_SEQUENCE $cert_root root of decoded data
	 * @return string
	 */
	public static function getExtVal_Subject(&$cert_root) {
		$is_v1 = false;
		if($cert_root->content[0]->findContext(0) === null)
			$is_v1 = true;
		
		return $cert_root->content[0]->content[$is_v1 ? 4 : 5];
	}
	
	/**
	 * Get subject key identifier from decoded certificate data
	 *
	 * @param ASN1_SEQUENCE $cert_root root of decoded data
	 * @return ASN1_SEQUENCE
	 */
	public static function getExtVal_SubjectKeyIdentifier(&$cert_root) {
		$ret = new ASN1_SEQUENCE;
		
		$is_v1 = false;
		if($cert_root->content[0]->findContext(0) === null)
			$is_v1 = true;
		
		//Define subjKeyId
		$subjKeyId = null;
		if($cert_root->content[0]->findContext(3) !== null) {
			$extval_subjKeyId = self::findExtensionVal('subjectKeyIdentifier', $cert_root->content[0]->findContext(3)->content[0]);
			if($extval_subjKeyId !== null) {
				$subjKeyId = $extval_subjKeyId->content[0]->getContent();
			}
		}
		if($subjKeyId === null) {
			$subjPubKey = $cert_root->content[0]->content[$is_v1 ? 5 : 6]->content[1]->getNormalizedBitstring();
			$subjKeyId = ASN1::hex_str2bin(sha1($subjPubKey));
		}
		
		//Write keyIdentifier
		$ret->content['keyIdentifier'] = new ASN1_OCTETSTRING( $subjKeyId );
		$ret->content['keyIdentifier']->setType(0, false, ASN1_CLASSTYPE_CONTEXT);
		
		//Copy subject
		$subject = $cert_root->content[0]->content[$is_v1 ? 4 : 5];
		
		//Write into authorityCertIssuer ([4] EXPLICIT Name)
		$ret->content['authorityCertIssuer'] = new ASN1_SEQUENCE; //it's GeneralNames
		$ret->content['authorityCertIssuer']->setType(1, true, ASN1_CLASSTYPE_CONTEXT);
		$ret->content['authorityCertIssuer']->content[0] = new ASN1_SEQUENCE; //it's EXPLICIT Name
		$ret->content['authorityCertIssuer']->content[0]->setType(4, true, ASN1_CLASSTYPE_CONTEXT);
		$ret->content['authorityCertIssuer']->content[0]->content[0] = $subject;
		
		//Copy serial
		$serial = $cert_root->content[0]->content[$is_v1 ? 0 : 1]->content;
		
		//Write into authorityCertSerialNumber
		$ret->content['authorityCertSerialNumber'] = new ASN1_INT( $serial );
		$ret->content['authorityCertSerialNumber']->setType(2, false, ASN1_CLASSTYPE_CONTEXT);
		
		return $ret;
	}
	
	/**
	 * Parse decoded certificate data into array
	 *
	 * @param ASN1_SEQUENCE $cert_root root of decoded data
	 * @return array @see https://www.ietf.org/rfc/rfc2459.txt
	 */
	public static function parse(&$cert_root) {
		$cert = array();
		$cert['signature'] = $cert_root->content[2]->getNormalizedBitstring();
		$cert['signatureAlgorithm'] = self::parse_AlgorithmIdentifier($cert_root->content[1]);
		$is_v1 = false;
		if($cert_root->content[0]->findContext(0) === null)
			$is_v1 = true;
		
		$cert['tbsCertificate'] = array();
		$tbsCert = & $cert['tbsCertificate'];
		$tbsCert['version'] = ($is_v1 ? 1 : ($cert_root->content[0]->findContext(0)->content[0]->content + 1));
		$tbsCert['serialNumber'] = $cert_root->content[0]->content[$is_v1 ? 0 : 1]->content;
		$tbsCert['signature'] = self::parse_AlgorithmIdentifier($cert_root->content[0]->content[$is_v1 ? 1 : 2]);
		$tbsCert['issuer'] = self::parse_Name($cert_root->content[0]->content[$is_v1 ? 2 : 3]);
		$tbsCert['validity'] = array();
		$tbsCert['validity']['notBefore'] = $cert_root->content[0]->content[$is_v1 ? 3 : 4]->content[0]->content;
		$tbsCert['validity']['notAfter'] = $cert_root->content[0]->content[$is_v1 ? 3 : 4]->content[1]->content;
		$tbsCert['subject'] = self::parse_Name($cert_root->content[0]->content[$is_v1 ? 4 : 5]);
		
		$tbsCert['subjectPublicKeyInfo'] = array();
		$subjPubKeyInfo = & $tbsCert['subjectPublicKeyInfo'];
		$subjPubKeyInfo['algorithm'] = self::parse_AlgorithmIdentifier($cert_root->content[0]->content[$is_v1 ? 5 : 6]->content[0]);
		$subjPubKeyInfo['subjectPublicKey'] = $cert_root->content[0]->content[$is_v1 ? 5 : 6]->content[1]->getNormalizedBitstring();
		//RSA key - n, e
		if($subjPubKeyInfo['algorithm']['algorithm'] == 'rsaEncryption') {
			$subjPubKeyInfo['subjectPublicKey_RSA'] = array();
			$subjPubKeyInfo['subjectPublicKey_RSA']['modulus'] = $cert_root->content[0]->content[$is_v1 ? 5 : 6]->content[1]->content[0]->content[0]->getContent(); //n
			$subjPubKeyInfo['subjectPublicKey_RSA']['publicExponent'] = $cert_root->content[0]->content[$is_v1 ? 5 : 6]->content[1]->content[0]->content[1]->getContent(); //e
		}
		
		if($cert_root->content[0]->findContext(1) !== null) {
			$tbsCert['issuerUniqueIdentifier'] = $cert_root->content[0]->findContext(1)->getNormalizedBitstring();
		}
		if($cert_root->content[0]->findContext(2) !== null) {
			$tbsCert['subjectUniqueIdentifier'] = $cert_root->content[0]->findContext(2)->getNormalizedBitstring();
		}
		if($cert_root->content[0]->findContext(3) !== null) {
			$tbsCert['extensions'] = self::parse_Extensions($cert_root->content[0]->findContext(3)->content[0]);
		}
		return $cert;
	}
	
	//Internal undocumented function
	protected static function findExtensionVal($ext_oid, & $exts) {
		if(preg_match("|^\d+(\.\d+)+$|s", $ext_oid)) {
			$is_oid = true;
		} else {
			$ext_name = $ext_oid;
			$ext_oid = OID::getOIDFromName($ext_name);
			$is_oid = !is_null($ext_oid);
		}
		
		foreach($exts->content as $k => $v) {
			$EXT_OID = $v->content[0]->content;
			if($is_oid ? ($EXT_OID == $ext_oid) : (OID::getNameFromOID($EXT_OID) == $ext_name)) {
				$hasCritical = (get_class($v->content[1]) == 'ASN1_BOOL');
				$extValue = $v->content[$hasCritical ? 2 : 1];
				return $extValue;
			}
		}
		return null;
	}
	
	//Internal undocumented function
	protected static function parse_Extensions($exts) {
		$extensions = array();
		
		foreach($exts->content as $k => $v) {
			//TIP:  $v - it's seq, one of many;  $extValue - it's octet string !!!
			$extName = OID::getNameFromOID($v->content[0]->content);
			$extensions[$extName] = array();
			$ext = &$extensions[$extName];
			if(get_class($v->content[1]) == 'ASN1_BOOL') {
				$hascritical = true;
				$ext['critical'] = $v->content[1]->content;
			} else {
				$hascritical = false;
			}
			$extValue = $v->content[$hascritical ? 2 : 1];
			if(get_class($extValue) == 'ASN1_OCTETSTRING') {
				switch($extName) {
					case 'basicConstraints':
						for($i = 0 ; $i < count($extValue->content[0]->content) ; $i++) {
							if(get_class($extValue->content[0]->content[$i]) == 'ASN1_BOOL')
								$ext['value']['CA'] = $extValue->content[0]->content[$i]->content;
							if(get_class($extValue->content[0]->content[$i]) == 'ASN1_INT')
								$ext['value']['pathLenConstraint'] = $extValue->content[0]->content[$i]->content;
						}
						break;
					case 'certificatePolicies':
						foreach($extValue->content[0]->content as $k => $pi) {
							$ext['value'][$k]['policyIdentifier'] = OID::getNameFromOID($pi->content[0]->content);
							if(count($pi->content) > 1) {
								foreach($pi->content[1]->content as $pq_k=>$pq_v) {
									$ext['value'][$k]['policyQualifiers'][$pq_k]['policyQualifierId'] = OID::getNameFromOID($pq_v->content[0]->content);
									$ext['value'][$k]['policyQualifiers'][$pq_k]['qualifier'] = self::parse_Any($pq_v->content[1]);
								}
							}
						}
						break;
					case 'subjectKeyIdentifier':
						$ext['value'] = $extValue->content[0]->getContent();
						break;
					case 'authorityKeyIdentifier':
						if($extValue->content[0]->findContext(0) !== null)
							$ext['value']['keyIdentifier'] = $extValue->content[0]->findContext(0)->getContent();
						if($extValue->content[0]->findContext(1) !== null)
							$ext['value']['authorityCertIssuer'] = self::parse_GeneralNames($extValue->content[0]->findContext(1));
						if($extValue->content[0]->findContext(2) !== null)
							$ext['value']['authorityCertSerialNumber'] = $extValue->content[0]->findContext(2)->content;
						break;
					case 'keyUsage':
						$key_usage = $extValue->content[0];
						$ext['value'] = self::parse_Bits($key_usage->content, X509::getKeyUsagesBits());
						break;
					case 'extKeyUsage':
						$ext_usages = $extValue->content[0];
						foreach($ext_usages->content as $k => $v) {
							$ext['value'][OID::getNameFromOID($v->content)] = 1;
						}
						break;
					case 'subjectAltName':
					case 'issuerAltName':
						$ext['value'] = self::parse_GeneralNames(@$extValue->content[0]);
						break;
					case 'netscape-cert-type':
						$cert_type = $extValue->content[0];
						$ext['value'] = self::parse_Bits($cert_type->content, X509::getNsCertTypes());
						break;
					case 'netscape-comment':
						$ext['type'] = self::parse_Any($extValue->content[0]);
						break;
					//case 'netscape-ca-revocation-url':
					case 'cRLDistributionPoints':
						$ext['value'] = array();
						foreach($extValue->content[0]->content as $k => $v) {
							if($v->findContext(0) !== null) {
								$dp = $v->findContext(0)->content[0];
								if($dp->getTag() == 0) {
									$ext['value'][$k]['distributionPoint']['fullName'] = self::parse_GeneralNames($dp);
								} else if($dp->getTag() == 1) {
									$ext['value'][$k]['distributionPoint']['nameRelativeToCRLIssuer'] = self::parse_RelDistName($dp);
								}
							}
							
							if($v->findContext(1) !== null) {
								$reason = $v->findContext(1);
								$ext['value'][$k]['reasons'] = self::parse_Bits($reason->content, X509::getREvokeReasonBits());
							}
							
							if($v->findContext(2) !== null) {
								$ext['value'][$k]['cRLIssuer'] = self::parse_GeneralNames($v->findContext(2));
							}
						}
						break;
					case 'authorityInfoAccess':
					case 'subjectInfoAccess':
						$ext['value'] = array();
						foreach($extValue->content[0]->content as $k => $v) {
							$ext['value'][OID::getNameFromOID($v->content[0]->content)] = self::parse_GeneralName($v->content[1]);
						}
						break;
					default:
						$ext['value'] = $extValue->getContent();
						break;
				}
			}
		}
		
		return $extensions;
	}
	
	//Internal undocumented function
	protected static function parse_GeneralNames(&$a) {
		if($a === null)
			return null;
		
		$gns = array();
		foreach($a->content as $k => $v) {
			$gns[$k] = self::parse_GeneralName($v);
		}
		return $gns;
	}
	
	//Internal undocumented function
	protected static function parse_GeneralName(&$v) {
		$gn = array();
		switch($v->getTag()) {
			case 0:
				$gn['otherName'][OID::getNameFromOID($v->content[0]->content)] = $v->content[1]->content[0]->getContent();
				// check: is value is explited?
				break;
			case 1:
				$gn['rfc822Name'] = $v->getContent(); //IA5String
				break;
			case 2:
				$gn['dNSName'] = $v->getContent(); //IA5String
				break;
			// case 3: //x400Address (ORAddress)
			case 4:
				$gn['directoryName'] = self::parse_Name($v->content[0]);
				break;
			case 5:
				$gn['ediPartyName'] = array();
				if($v->findContext(0) !== null)
					$gn['ediPartyName']['nameAssigner'] = self::parse_Any($v->findContext(0)->content[0]);
				$gn['ediPartyName']['partyName'] = self::parse_Any($v->findContext(1)->content[0]);
				// check: are values is explited?
				break;
			case 6:
				$gn['uniformResourceIdentifier'] = $v->getContent(); //IA5String
				break;
			case 7:
				$gn['iPAddress'] = self::ipToString($v->getContent());
				break;
			case 8:
				$gn['registeredID'] = OID::getNameFromOID($v->content);
				break;
			default:
				$gn[$v->getTag()] = $v->getContent();
				break;			
		}
		return $gn;
	}
	
	//Internal undocumented function
	protected static function parse_Name(&$a) {
		$dn = array();
		
		foreach($a->content as $k => $v) {
			$dn[$k] = self::parse_RelDistName($v);
		}
		
		return $dn;
	}
	
	//Internal undocumented function
	protected static function parse_RelDistName($a) {
		$rdn = array();
		
		foreach($a->content as $k => $v) {
			$rdn[OID::getNameFromOID($v->content[0]->content)] = self::parse_Any($v->content[1]);
		}
		
		return $rdn;
	}
	
	//Internal undocumented function
	protected static function parse_Bits($str, $bitsmap) {
		$b = array();
		for($i = 0 ; $i < strlen($str) ; $i++) {
			for($bit = 0 ; $bit < 8 ; $bit++) {
				if(array_key_exists($i*8 + $bit, $bitsmap)) {
					$b[ $bitsmap[$i*8+$bit] ] = ( (ord($str[$i]) & (int)pow(2, 7-$bit)) == (int)pow(2, 7-$bit) );
				}
			}
		}
		foreach($bitsmap as $bit => $name) {
			if(!array_key_exists($name, $b))
				$b[$name] = false;
		}
		return $b;
	}
	
	//Internal undocumented function
	protected static function ipToString($s) {
		//$s - octet string (length=4)
		//need to show like 127.0.0.1
		$ip = array();
		for($i = 0 ; $i < strlen($s) ; $i++) {
			$ip[] = ord($s[$i]);
		}
		return explode('.', $ip);
	}
	
	//Internal undocumented function
	protected static function parse_AlgorithmIdentifier($x) {
		$ai = array();
		$ai['algorithm'] = OID::getNameFromOID($x->content[0]->content);
		if(count($x->content) > 1)
			$ai['parameters'] = self::parse_Any($x->content[1]);
		return $ai;
	}
	
	//Internal undocumented function
	protected static function parse_Any($x) {
		return array( 'type' => get_class($x), 'val' => $x->getContent() );
	}
}

?>