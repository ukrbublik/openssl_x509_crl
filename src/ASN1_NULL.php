<?php

namespace Ukrbublik\openssl_x509_crl;

use Ukrbublik\openssl_x509_crl\ASN1;

/*
 * ANS1 NULL type
 */
class ASN1_NULL extends ASN1
{
    protected $tag = 0x5;
    protected $isConstructed = false;
    public $content = null;
    
    protected function encodeSimpleContent() {
        return $this->content;
    }
}
