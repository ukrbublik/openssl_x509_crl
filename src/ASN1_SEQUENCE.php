<?php

namespace Ukrbublik\openssl_x509_crl;

use Ukrbublik\openssl_x509_crl\ASN1;

/**
 *  ANS1 SEQUENCE type
 */
class ASN1_SEQUENCE extends ASN1
{
    protected $tag = 0x10;
    protected $isConstructed = true;
    public $content = array();
    
    protected function encodeSimpleContent()
    { }
}
