<?php

namespace Ukrbublik\openssl_x509_crl;

use Ukrbublik\openssl_x509_crl\ASN1_GENERALTIME;

/*
 * ANS1 UTC time type
 */
class ASN1_UTCTIME extends ASN1_GENERALTIME
{
    protected $tag = 0x17;
    protected $isConstructed = false;
    protected $timeZone = 'UTC';
    protected $yearDigits = 2;
}
