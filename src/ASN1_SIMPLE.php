<?php

namespace Ukrbublik\openssl_x509_gencrl;

use Ukrbublik\openssl_x509_gencrl\ASN1;

/**
 * ANS1 default type
 */
class ASN1_SIMPLE extends ASN1
{
    /**
     * Constructor
     *
     * @param string $str content
     */
    public function __construct($str = null) {
        $this->content = $str;
    }
    
    protected function encodeSimpleContent() {
        return $this->content;
    }
}
