<?php

/**
 * ASN1 Decoder & Encoder
 * 
 * @see http://www.umich.edu/~x509/ssleay/asn1_intro.html ASN1 specification
 * @see http://www.umich.edu/~x509/ssleay/layman.html ASN1 specification
 * @see http://lionet.info/asn1c/asn1c.cgi ASN1 decoder
 * @see http://phpseclib.sourceforge.net/x509/asn1parse.php ASN1 decoder
 * @see http://www.itu.int/en/ITU-T/asn1/Pages/Tools.aspx ASN1 tools
 * 
 */

namespace Ukrbublik\openssl_x509_gencrl;

/**
 * ASN1 class types
 */
define('ASN1_CLASSTYPE_UNIVERSAL', 0x00);
define('ASN1_CLASSTYPE_APPLICATION', 0x40);
define('ASN1_CLASSTYPE_CONTEXT', 0x80);
define('ASN1_CLASSTYPE_PRIVATE', 0xC0);


/**
 * Base abstract class for ASN1
 */
abstract class ASN1
{
	/** @var array List of ASN1 class types */
	protected static $ClassTypes = array(
		ASN1_CLASSTYPE_UNIVERSAL,
		ASN1_CLASSTYPE_APPLICATION,
		ASN1_CLASSTYPE_CONTEXT,
		ASN1_CLASSTYPE_PRIVATE,
	);
	
	/** @var int ASN1 tag (type). Every ASN1_* class has its own tag */
	protected $tag = 0;
	/** @var int ASN1 class type, see ASN1::$ClassTypes */
	protected $classType = ASN1_CLASSTYPE_UNIVERSAL;
	/** @var bool Is constructed type or primitive? */
	protected $isConstructed = false;
	/** @var string|array Content. String or array of ASN1_* objects */
	public $content = null;
	
	/**
	 * Get tag
	 *
	 * @return int
	 */
	public function getTag() {
		return $this->tag;
	}
	/**
	 * Get content
	 *
	 * @return int
	 */
	public function getContent() {
		return $this->content;
	}
	/**
	 * Set type vars (usually overwrite right after construct)
	 *
	 * @param int $tag
	 * @param bool $isConstructed
	 * @param int $classType
	 */
	public function setType($tag, $isConstructed = null, $classType = null) {
		$this->tag = $tag;
		if(!is_null($isConstructed)) {
			$this->isConstructed = (bool)$isConstructed;
		}
		if(!is_null($classType)) {
			if(in_array($classType, self::$ClassTypes))
				$this->classType = $classType;
			else
				throw new \Exception('Classtype ' . $classType . ' is unknown!');
		}
	}
	
	/**
	 * Get 1st byte describing type
	 * @see ASN1::encode()
	 *
	 * @return int
	 */
	private function getTypeByte() {
		return ($this->tag | $this->classType | ($this->isConstructed ? 0x20 : 0));
	}
	
	/**
	 * Find ASN1_* object of classtype CONTEXT by tag in content
	 *
	 * @param int $tag
	 *
	 * @return null|object
	 */
	public function findContext($tag) {
		$c = null;
		if(is_array($this->content)) {
			foreach($this->content as $k => $v) {
				if(!($v instanceof ASN1))
					continue;
				if($v->classType == ASN1_CLASSTYPE_CONTEXT && $v->tag == $tag) {
					$c = $v;
					break;
				}
			}
		}
		return $c;
	}
	
	
	/**
	 * Decodes data to content
	 *
	 * @uses ASN1::checkIsConstructed()
	 * @uses ASN1::decodeSimple()
	 * @uses ASN1::decodeConstructed()
	 *
	 * @param string $str data to decode
	 * @param int $start offset
	 * @param int $length length
	 */
	public function decode(&$str, $start, $length) {
		//bit & octet strings can be structed!
		if($this->isConstructed  ||  $this->classType == ASN1_CLASSTYPE_UNIVERSAL && ($this->tag == 0x3 || $this->tag == 0x4)) {
			$isConstructed = $this->checkIsConstructed($str, $start, $length);
		} else {
			$isConstructed = false;
		}
		
		if(!$isConstructed) {
			$this->decodeSimple($str, $start, $length);
		} else {
			$this->decodeConstructed($str, $start, $length);
		}
	}
	
	/**
	 * Defines if data is structed or simple
	 * Note: Bit & octet strings can also be structed!
	 * @see ASN1::decode()
	 *
	 * @param string $str data to decode
	 * @param int $start offset
	 * @param int $length length
	 *
	 * @return bool
	 */
	protected function checkIsConstructed(&$str, $start, $length) {
		if($length == 0)
			return false;
		
		//don't count 1st zero bit for BITSTRING
		if($this->tag == 0x3 && $this->classType == ASN1_CLASSTYPE_UNIVERSAL && ord($str[$start]) == 0) {
			$start++;
			$length--;
		}
		
		$offset = $start;
		$rest = $length;
		while($rest > 0) {
			$offset++;
			$rest--;
			if($rest <= 0) {
				$is_dividable = false;
				break;
			}
			
			$len = ord($str[$offset]);
	    	$offset++;
	    	$rest--;
			if($len >= 128) { //long form
				//leave only 7 bits
		    	$len_octets = ($len & 127);
		    
		    	if($rest > 0xFFFFFF + 4)
		    		$rest_len_octets = 4;
		    	else if($rest > 0xFFFF + 3)
		    		$rest_len_octets = 3;
		    	else if($rest > 0xFF + 2)
		    		$rest_len_octets = 2;
		    	else
		    		$rest_len_octets = 1;
		    	
		    	if($len_octets > $rest_len_octets) {
					$is_dividable = false;
					break;
		    	}
		    	
		    	$len = 0;
		    	for($i = $len_octets - 1 ; $i >= 0  ; $i--) {
		    		$len += ord($str[$offset+$i]) * (int)pow(2, 8*($len_octets - 1 - $i));
		    	}
		    	$offset += $len_octets;
		    	$rest -= $len_octets;
		    }
		    
		    $offset += $len;
		    $rest -= $len;
		}
		$is_dividable = ((!isset($is_dividable) || $is_dividable != false) && $rest == 0);
		return $is_dividable;
	}
	
	/**
	 * Decode simple data to content
	 * @see ASN1::decode()
	 *
	 * @param string $str data to decode
	 * @param int $start offset
	 * @param int $length length
	 */
	protected function decodeSimple(&$str, $start, $length) {
		$this->content = substr($str, $start, $length);
	}
	
	/**
	 * Decode structed data to content
	 * @see ASN1::decode()
	 *
	 * @param string $str data to decode
	 * @param int $start offset
	 * @param int $length length
	 */
	protected function decodeConstructed(&$str, $start, $length) {
		$this->content = array();
		$offset = $start;
		$cont_i = 0;
		while( ($offset - $start) < $length ) {
			//1. Parse tag
			$_tag = ord($str[$offset]);
			$tag = ($_tag & 0x1F); //only 5 bits
			$isConstructed = (($_tag & 0x20) == 0x20);
			$classType = ($_tag & 0xC0);
			$offset++;
			
			//2. Parse length
			$len = ord($str[$offset]);
			if($len < 128) {
				//short form
		    	$offset++;
		    } else {
				//long form
		    	$len_octets = ($len & 127); //only 7 bits
		    	$offset++;
		    	$len = 0;
		    	for($i = $len_octets - 1 ; $i >= 0  ; $i--)
		    	{
		    		$len += ord($str[$offset+$i]) * (int)pow(2, 8*($len_octets - 1 - $i));
		    	}
		    	$offset += $len_octets;
		    }
			
			//3. Parse content
			if($classType != ASN1_CLASSTYPE_UNIVERSAL) {
				$this->content[$cont_i] = new ASN1_SIMPLE();
				$this->content[$cont_i]->setType($tag, $isConstructed, $classType);
			} else {
				switch($tag) {
					case 0x10:
						$this->content[$cont_i] = new ASN1_SEQUENCE;
						break;
					case 0x11:
						$this->content[$cont_i] = new ASN1_SET;
						break;
					case 0x5;
						$this->content[$cont_i] = new ASN1_NULL;
						break;
					case 0xC:
						$this->content[$cont_i] = new ASN1_UTF8STRING;
						break;
					case 0x14:
						$this->content[$cont_i] = new ASN1_TELETEXSTRING;
						break;
					case 0x12:
					case 0x13:
					case 0x16:
						$this->content[$cont_i] = new ASN1_ASCIISTRING("", $tag);
						break;
					case 0x3:
						$this->content[$cont_i] = new ASN1_BITSTRING;
						break;
					case 0x1:
						$this->content[$cont_i] = new ASN1_BOOL;
						break;
					case 0x2:
						$this->content[$cont_i] = new ASN1_INT;
						break;
					case 0x6:
						$this->content[$cont_i] = new ASN1_OID;
						break;
					case 0xA:
						$this->content[$cont_i] = new ASN1_ENUM;
						break;
					case 0x4:
						$this->content[$cont_i] = new ASN1_OCTETSTRING;
						break;
					case 0x17:
						$this->content[$cont_i] = new ASN1_UTCTIME;
						break;
					case 0x18:
						$this->content[$cont_i] = new ASN1_GENERALTIME;
						break;
					default:
						$this->content[$cont_i] = new ASN1_SIMPLE();
						$this->content[$cont_i]->setType($tag, $isConstructed, $classType);
						break;
				}
			}
			$this->content[$cont_i]->decode($str, $offset, $len);
			$offset += $len;
			
			$cont_i++;
		}
	}
	
	
	/**
	 * Encode content (to final data)
	 *
	 * @return string
	 */
	public function encode() {
		$content = $this->encodeContent();
		return chr($this->getTypeByte()) . ASN1::length_der(strlen($content)) . $content;
	}
	
	/**
	 * Encode content
	 * @see ASN1::encode()
	 *
	 * @return string
	 */
	protected function encodeContent() {
		if(is_array($this->content)) {
			$content = "";
			foreach($this->content as $k => $v) {
				if(is_object($v) && $v instanceof ASN1) {
					$content .= $v->encode();
				}
			}
			return $content;
		} else {
			return $this->encodeSimpleContent();
		}
	}
	
	/**
	 * Encode simple content
	 * @see ASN1::encodeContent()
	 *
	 * @return string
	 */
	abstract protected function encodeSimpleContent();
	
	
	/**
	 * Util: Get binary-encoded value of length of content
	 *
	 * @param int $len
	 * @return int
	 */
	public static function length_der($len) {
		$len_DER = "";
	    
	    if($len < 128) { //short form
	    	$len_DER = chr($len);
	    } else { //long form
	    	for($i = 0 ; $i < 4 ; $i++) {
	    		if( $len == 0 || $len >= (int)pow(2, 8*$i) )
	    			$len_DER .= chr( ($len >> (8*$i)) & 255 );
	    		else
	    			break;
	    	}
	    	$len_DER = chr(128 | $i) . strrev($len_DER);
	    }
    
		return $len_DER;
	}
	
	/**
	 * Util: Get binary-encoded decimal value.
	 * Big numbers are supported
	 *
	 * @param int $num
	 * @return string
	 */
	public static function dec2hex_der($num) {
		bcscale(0);
		if($num == 0)
			return chr(0);
		$hex = "";
		$isneg = ($num < 0);
		if($isneg) {
			$num = bcsub(substr($num, 1, strlen($num)-1), 1);		
		}
		while($num > 0) {
			$quot = bcdiv($num, 256);
			//$mod = bcmod($num, 256);
			$a = bcmul($quot, 256);
			$rest = bcsub($num, $a);
			
			$num = $quot;
			$hex .= chr($isneg ? (255 - $rest) : $rest);
		}
		if($rest >= 128 && !$isneg  ||  $rest < 128 && $isneg)
			$hex = $hex . chr($isneg ? 255 : 0);
		$hex = strrev($hex);
		
		return $hex;
	}
	
	/**
	 * Util: Get binary-decoded decimal value.
	 * Big numbers are supported
	 *
	 * @param string $s
	 * @return int
	 */
	public static function hex2dec_der($s) {
		bcscale(0);
		$num = 0;
		$len = strlen($s);
		$neg = (ord($s[0]) >= 128);
		for($i = $len - 1 ; $i >= 0  ; $i--) {
			$oct = ord($s[$i]);
			$num = bcadd($num, bcmul($oct, bcpow(256, ($len - 1 - $i))));
		}
		if($neg)
			$num = bcsub($num, bcpow(256, $len));
		
		return $num;
	}
	
	/**
	 * @deprecated
	 *
	 * @param 
	 * @return 
	 */
	public static function hex2dec_oid($s) {
		bcscale(0);
		$oid = array();
		$oct = ord($s[0]);
		$oid[] = ($oct - $oct%40) / 40;
		$oid[] = $oct%40;
		
		$j = 2;
		$temp = array();
		for($i = 1 ; $i < strlen($s) ; $i++) {
			if(!array_key_exists($j, $temp))
				$temp[$j] = array();
			$oct = ord($s[$i]);
			$temp[$j][] = ($oct & 127);
			if($oct < 128)
				$j++;
		}

		foreach($temp as $v_128) {
			$v = 0;
			foreach($v_128 as $a=>$b) {
				$v = bcadd($v, bcmul($b, bcpow(128, count($v_128) - 1 - $a)));
			}
			$oid[] = $v;
		}
	}
	
	/**
	 * Util: Convert hex-string to binary data
	 *
	 * @param string $str
	 * @return string
	 */
	public static function hex_str2bin($str) {
		if(preg_match("|^([0-9A-Fa-f]{2})+$|s", $str)) {
			$str_bin = "";
			for($i = 0 ; $i < strlen($str) ; $i+=2) {
				$str_bin .= chr(hexdec($str[$i] . $str[$i+1]));
			}
			return $str_bin;
		}
		else
			return $str;
	}
	
	/**
	 * Util: Convert binary data to hex-string
	 *
	 * @param string $bin
	 * @param string $delimeter
	 * @return string
	 */
	public static function hex_bin2str($bin, $delimeter = " ") {
		$str = "";
		for($i = 0 ; $i < strlen($bin) ; $i++) {
			if($i)
				$str .= $delimeter;
			$octet = dechex(ord($bin[$i]));
			$str .= (strlen($octet) == 1 ? "0" : "") . $octet;
		}
		return $str;
	}
}



?>