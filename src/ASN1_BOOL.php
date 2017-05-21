<?php

namespace Ukrbublik\openssl_x509_gencrl;

use Ukrbublik\openssl_x509_gencrl\ASN1;

/*
 * ANS1 bool type
 */
class ASN1_BOOL extends ASN1
{
    protected $tag = 0x1;
    protected $isConstructed = false;

    protected function encodeSimpleContent() {
        return ($this->content ? chr(0xff) : chr(0));
    }
    
    public function __construct($b = null) {
        if(!is_null($b)) {
            $this->content = (bool)$b;
        }
    }
    
    protected function decodeSimple(&$str, $start, $length) {
        $s = substr($str, $start, $length);
        $this->content = (ord($s[0]) != 0);
    }
}
