<?php

namespace Ukrbublik\openssl_x509_gencrl;

use Ukrbublik\openssl_x509_gencrl\ASN1_UTF8STRING;

/*
 * ANS1 T.61 (Teletex) string type
 */
class ASN1_TELETEXSTRING extends ASN1_UTF8STRING
{
    protected $tag = 0x14;
}
