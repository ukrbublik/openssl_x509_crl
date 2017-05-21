<?php

namespace Ukrbublik\openssl_x509_gencrl;

use Ukrbublik\openssl_x509_gencrl\ASN1;

/*
 * ANS1 int type
 */
class ASN1_INT extends ASN1
{
    protected $tag = 0x02;
    protected $isConstructed = false;
    
    /**
     * Constructor
     *
     * @param int $t int number
     */
    public function __construct($t = null) {
        if(!is_null($t)) {
            if(is_numeric($t)) {
                $this->content = /*(int)*/ $t;
            } else {
                throw new \Exception($t . ' is not INT');
            }
        }
    }
    
    protected function encodeSimpleContent() {
        return ASN1::dec2hex_der($this->content);
    }
    
    protected function decodeSimple(&$str, $start, $length) {
        $this->content = ASN1::hex2dec_der(substr($str, $start, $length));          
    }
}
