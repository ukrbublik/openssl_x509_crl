<?php

namespace Ukrbublik\openssl_x509_crl;

use Ukrbublik\openssl_x509_crl\ASN1;

/**
 *  ANS1 SET type
 */
class ASN1_SET extends ASN1
{
    protected $tag = 0x11;
    protected $isConstructed = true;
    public $content = array();

    protected function encodeSimpleContent()
    { }
}
