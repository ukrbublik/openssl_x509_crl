<?php

namespace Ukrbublik\openssl_x509_crl;

use Ukrbublik\openssl_x509_crl\ASN1;

/*
 * ANS1 generalized time type
 */
class ASN1_GENERALTIME extends ASN1
{
    protected $tag = 0x18;
    protected $isConstructed = false;
    /** @var int $timeZone time zone name */
    protected $timeZone = null;
    protected $yearDigits = 4;
    
    /**
     * Constructor
     *
     * @param int $t timestamp
     * @param string|int $tz timezone name or offset in seconds (to encode)
     */
    public function __construct($t = null, $tz = null) {
        if(!is_null($t)) {
            $this->content = (int)$t;
            if(is_numeric($tz)) {
                $tzn = timezone_name_from_abbr("", $tz);
                if($tzn !== false)
                    $this->timeZone = timezone_name_from_abbr("", $tzn);
            } else if(!is_null($tz)) {
                $this->timeZone = $tz;
            }
        }
    }
    
    protected function decodeSimple(&$str, $start, $length) {
        $t = substr($str, $start, $length); 
        if(preg_match("/^ (\d{2,4}) (0[1-9]|1[0-2]) (0[1-9]|[1-2][0-9]|30|31) ([0-1][0-9]|2[0-3]) ([0-5][0-9]) ([0-5][0-9]) Z $/sx", $t, $matches)) {   
            $this->yearDigits = strlen($matches[1]);
            $res = date_parse_from_format(($this->yearDigits == 2 ? "y" : "Y")."mdHis\Z", $t);
            if(!isset($res['error_count']) || !$res['error_count']) {
                $orig_tz = date_default_timezone_get();
                date_default_timezone_set('UTC');
                $this->timeZone = 'UTC';
                $ts = mktime($res['year'], $res['month'], $res['day'], $res['hour'], $res['minute'], $res['second']);
                date_default_timezone_set($orig_tz);
                $this->content = $ts;
            } else {
                throw new \Exception("Can't parse time from string '$t'! Parse errors: " . implode('; ', $res['errors']));
            }
        } else if(preg_match("/^ (\d{2,4}) (0[1-9]|1[0-2]) (0[1-9]|[1-2][0-9]|30|31) ([0-1][0-9]|2[0-3]) ([0-5][0-9]) ([0-5][0-9]) ([+-] ([0-1][0-9]|2[0-3]) ([0-5][0-9])) $/sx", $t, $matches)) {  
            $this->yearDigits = strlen($matches[1]);
            $res = date_parse_from_format(($this->yearDigits == 2 ? "y" : "Y")."mdHisO", $t);
            if(!isset($res['error_count']) || !$res['error_count']) {
                $orig_tz = date_default_timezone_get();
                if($res['is_localtime']) {
                    $tzn = timezone_name_from_abbr("", $res['zone'] * 60, $res['is_dst']);
                    if($tzn !== false) {
                        date_default_timezone_set($tzn);
                        $this->timeZone = $tzn;
                    }
                } else {
                    date_default_timezone_set('UTC');
                }
                $ts = mktime($res['year'], $res['month'], $res['day'], $res['hour'], $res['minute'], $res['second']);
                date_default_timezone_set($orig_tz);
                $this->content = $ts;
            } else {
                throw new \Exception("Can't parse time from string '$t'! Parse errors: " . implode('; ', $res['errors']));
            }
        } else {
            throw new \Exception("Can't parse time from string '$t'");
        }       
    }
    
    protected function encodeSimpleContent() {
        $ret = "";
        if($this->content) {
            $orig_tz = date_default_timezone_get();
            if($this->timeZone == 'UTC') {
                date_default_timezone_set('UTC');
                $ret = date(($this->yearDigits == 2 ? "y" : "Y")."mdHis\Z", $this->content);
            } else if($this->timeZone) {
                date_default_timezone_set($this->timeZone);
                $ret = date(($this->yearDigits == 2 ? "y" : "Y")."mdHisO", $this->content);
            } else {
                //use current timezone
                $ret = date(($this->yearDigits == 2 ? "y" : "Y")."mdHisO", $this->content);
            }
            date_default_timezone_set($orig_tz);
        }
        return $ret;
    }
}
