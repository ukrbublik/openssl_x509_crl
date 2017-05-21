<?php

namespace Ukrbublik\openssl_x509_gencrl;

use Ukrbublik\openssl_x509_gencrl\ASN1;

/*
 * ANS1 enum type
 */
class ASN1_ENUM extends ASN1_INT
{
    protected $tag = 0xA;
    protected $isConstructed = false;
    
    /**
     * Constructor
     *
     * @param int $t enum int value
     */
    public function __construct($t = null) {
        if(!is_null($t)) {
            if(is_int($t) && $t >= 0) {
                $this->content = $t;
            } else {
                throw new \Exception($t . ' is not ENUM');
            }
        }
    }
}
