<?php
error_reporting(E_ALL);
ini_set("display_errors", 1);
header("Content-Type: text/html; charset=utf-8");
require_once("../src/x509_cert.php");
require_once("../src/x509_crl.php");

//Check server requirements
X509::checkServer();

//Create CRL
$ci = array(
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
$crl_data = X509_CRL::create($ci, $ca_pkey, $ca_cert);
if(file_put_contents("test_crl.crl", $crl_data))
	echo "<b>CRL generated and saved to 'test_crl.crl'.</b><br><hr>";

//Parse CA certificate
$cert_data = X509::pem2der(file_get_contents('ca_cert.cer'));
$cert_root = X509_CERT::decode($cert_data);
$cert = X509_CERT::parse($cert_root);
echo "<b>Parsed 'ca_cert.cer':</b><br><pre>";
var_dump($cert);
echo "</pre><hr>";

//Parse VeriSign certificate
$cert_data = file_get_contents('test_cert.cer');
$cert_root = X509_CERT::decode($cert_data);
$cert = X509_CERT::parse($cert_root);
echo "<b>Parsed 'test_cert.cer':</b><br><pre>";
var_dump($cert);
echo "</pre><hr>";

?>
