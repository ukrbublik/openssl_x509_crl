<?php

error_reporting(E_ALL);
ini_set("display_errors", 1);

require_once("../src/x509_cert.php");
require_once("../src/x509_crl.php");

X509::checkServer();

$cert_data = file_get_contents('test_cert.cer');
$cert_root = X509_CERT::decode($cert_data);
$cert = X509_CERT::parse($cert_root);
var_dump($cert);

/*
$ci = array(
..todo..
	'no' => number of CRL,<br>
	'version' => CRL format version, 1 or 2,<br>
	'days' => CRL validity in days from date of creation,<br>
	'alg' => OPENSSL_ALGO_*,<br>
	'revoked' => array(
		array(
			'serial' => S/N of revoked cert,<br>
			'rev_date' => date of revokation, timestamp,<br>
			'reason' => code of revokation reason, see X509::getRevokeReasonCodeByName(),<br>
			'compr_date' => date when certifacate became compromised, timestamp,<br>
			'hold_instr' => code of hold instruction, see X509::getHoldInstructionCodeByName(),<br>
		)
	)
);
$ca_pkey = openssl_pkey_get_private(..todo..);
$ca_data = ..todo..
$crl_data = X509_CRL::create($ci, $ca_pkey, $ca_data);
file_put_contents("test_crl.crl");
*/

?>
