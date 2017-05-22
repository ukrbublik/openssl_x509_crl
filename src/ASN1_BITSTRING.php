<?php

namespace Ukrbublik\openssl_x509_crl;

use Ukrbublik\openssl_x509_crl\ASN1;

/*
 * ANS1 bit string type
 */
class ASN1_BITSTRING extends ASN1
{
    protected $tag = 0x3;
    protected $isConstructed = false;
    public $content = "";
    /** @var int unused bits */
    protected $unused_bits = 0;
    
    /**
     * Constructor
     *
     * @param string $str string
     * @param int $unused_bits unused bits
     * @param bool $do_padding
     */
    public function __construct($str = "", $unused_bits = 0, $do_padding = true) {
        if($str === false) {
            $this->content = array();
            $this->unused_bits = $unused_bits;
        } else {
            if($unused_bits && $do_padding) {
                $last_octet = ord($str[strlen($str) - 1]);
                $last_octet = $last_octet << $unused_bits;
                $str[strlen($str) - 1] = chr($last_octet);
            }
            $this->content = $str;
            $this->unused_bits = $unused_bits;
        }
    }
    
    protected function encodeSimpleContent() {
        return $this->content;
    }
    
    protected function encodeContent() {
        return chr($this->unused_bits) . parent::encodeContent();
    }
    
    protected function decodeConstructed(&$str, $start, $length) {
        if($length > 0) {
            $this->unused_bits = ord($str[$start]);
            parent::decodeConstructed($str, $start + 1, $length - 1);
        }
    }
    
    protected function decodeSimple(&$str, $start, $length) {
        if($length > 0) {
            $this->unused_bits = ord($str[$start]);
            parent::decodeSimple($str, $start + 1, $length - 1);
        }
    }
    
    /**
     * Get normalized bit string
     *
     * @return string
     */
    public function getNormalizedBitstring() {
        $encoded_content = parent::encodeContent();
        $len = strlen($encoded_content);
        if($this->unused_bits > 0 && $len > 0) {
            $norm = $encoded_content;
            $last_octet = ord($norm[$len - 1]);
            $last_octet = $last_octet >> $this->unused_bits;
            $norm[$len - 1] = chr($last_octet);
            return $norm;
        } else {
            return $encoded_content;
        }
    }
}
