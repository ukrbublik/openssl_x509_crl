# openssl_x509_gencrl

If you want to create own Certification authority (CA) on pure PHP with OpenSSL extension, 
you need a function to create certificate revocation list (CRL) which is missing in OpenSSL extension.<br>
This lib implements such function - <b>openssl_x509_gencrl()</b>

<h2>Usage example:</h2>
<pre>$ci = array(
	'no' => 1,
	'version' => 2,
	'days' => 30,
	'alg' => OPENSSL_ALGO_SHA1,
	'revoked' => array(
		array(
			'serial' => '101',
			'rev_date' => time(),
			'reason' => X509::getRevokeReasonCodeByName("cessationOfOperation"),
			'compr_date' => strtotime("-1 day"),
			'hold_instr' => null,
		)
	)
);
$ca_pkey = openssl_pkey_get_private(file_get_contents('ca_key.key'));
$ca_cert = X509::pem2der(file_get_contents('ca_cert.cer'));
$crl_data = openssl_x509_gencrl($ci, $ca_pkey, $ca_cert);
//$crl_data contains CRL in DER format
</pre>
