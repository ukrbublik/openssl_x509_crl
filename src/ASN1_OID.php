<?php

namespace Ukrbublik\openssl_x509_crl;

use Ukrbublik\openssl_x509_crl\ASN1;

/*
 * ANS1 OID type
 * @see class OID
 */
class ASN1_OID extends ASN1
{
    protected $tag = 0x6;
    protected $isConstructed = false;
    public $content = "";
    
    /**
     * Constructor
     *
     * @param string $oid OID
     */
    public function __construct($oid = null) {
        if(!is_null($oid)) {
            if(preg_match("|^\d+(\.\d+)+$|s", $oid)) {
                $this->content = $oid;
            } else {
                throw new \Exception($oid . ' is not OID');
            }
        }
    }
    
    protected function encodeSimpleContent() {
        $oid = explode('.', $this->content);
        $oid_DER = "";
        
        $oid_DER .= chr( 40*$oid[0] + $oid[1] );
        for($i = 2 ; $i < count($oid) ; $i++) {
            $num = $oid[$i];
            $num_DER = "";

            for($j = 0 ; $j < 4 ; $j++) {
                if( $num == 0 || $num >= (int)pow(2, 7*$j) ) {
                    $num_DER .= chr( (($num >> (7*$j)) & 127) | ($j ? 128 : 0) );
                }
                else
                    break;
            }
            $num_DER = strrev($num_DER);

            $oid_DER .= $num_DER;

        }
        
        return $oid_DER;
    }
    
    protected function decodeSimple(&$str, $start, $length) {
        bcscale(0);
        $s = substr($str, $start, $length);
        $oid = array();
        
        $oct = ord($s[0]);
        $oid[] = ($oct - $oct%40) / 40;
        $oid[] = $oct%40;
        
        $j = 0;
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
        
        $this->content = implode('.', $oid);
    }
}
