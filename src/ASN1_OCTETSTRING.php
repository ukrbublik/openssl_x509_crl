<?php

namespace Ukrbublik\openssl_x509_crl;

use Ukrbublik\openssl_x509_crl\ASN1;

/*
 * ANS1 octet string type
 */
class ASN1_OCTETSTRING extends ASN1
{
    protected $tag = 0x4;
    protected $isConstructed = false;
    public $content = "";
    
    /**
     * Constructor
     *
     * @param string $str string
     * @param bool $twodots not used
     */
    public function __construct($str = "", $twodots = false) {
        if($str === false) {
            $this->content = array();
        } else if(preg_match("|^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+$|s", $str) /* || $twodots*/) {
            $octets = explode(':', $str);
            foreach($octets as &$v) {
                $v = chr(hexdec($v));
            }
            $this->content = implode($octets);
        } else {
            $this->content = $str;
        }
    }
    
    protected function encodeSimpleContent() {
        return $this->content;
    }
}
