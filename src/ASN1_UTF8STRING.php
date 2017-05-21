<?php

namespace Ukrbublik\openssl_x509_gencrl;

use Ukrbublik\openssl_x509_gencrl\ASN1;

/*
 * ANS1 UTF-8 string type
 */
class ASN1_UTF8STRING extends ASN1
{
    protected $tag = 0xC;
    protected $isConstructed = false;
    public $content = "";
    
    /**
     * Constructor
     *
     * @param string $str string
     * @param string $cp codepage to convert $str from
     */
    public function __construct($str = "", $cp = null) {
        $this->content = (is_null($cp) ? $str : iconv($cp, "utf-8", $str));
    }
    
    protected function encodeSimpleContent() {
        return $this->content;
    }
}
