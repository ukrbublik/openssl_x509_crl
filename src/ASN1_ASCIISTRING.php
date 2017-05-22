<?php

namespace Ukrbublik\openssl_x509_crl;

use Ukrbublik\openssl_x509_crl\ASN1;

/*
 * ANS1 ASCII string type
 */
class ASN1_ASCIISTRING extends ASN1
{
    protected $isConstructed = false;
    public $content = "";
    
    /**
     * Constructor
     *
     * @param string $str string
     * @param int $tag tag (ASN1 type)
     */
    public function __construct($str = "", $tag = null) {
        $this->content = $str;
        if($tag !== null && ($tag == 0x12 || $tag == 0x13 || $tag == 0x16)) {
            $this->tag = $tag;
        } else {
            if(preg_match("|^[0-9 ]*$|s", $str)) {
                // numeric
                $this->tag = 0x12;
                
            }
            if(preg_match("|^[a-zA-Z0-9 '()+\-,./:=?]*$|s", $str)) {
                // printable
                $this->tag = 0x13;
            } else {
                // ASCII (IA5)
                $this->tag = 0x16;
            }
        }
    }
    
    protected function encodeSimpleContent() {
        return $this->content;
    }
}
