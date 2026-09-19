<?php

declare(strict_types=1);

namespace Komma\Asice\Ocsp;

use Komma\Asice\Asn1\Der;
use Komma\Asice\Crypto\Certificate;
use RuntimeException;

/**
 * Asks the issuer's OCSP responder whether the signing certificate was valid
 * at the moment of signing, and keeps the answer. That answer, embedded in
 * the container, is what turns a signature into a long-term one: a verifier
 * years later does not have to reach any service.
 *
 * SK's public responder (aia.sk.ee) answers without a service agreement;
 * ocsp.sk.ee requires one and an access certificate.
 */
final class OcspClient
{
    public function __construct(
        private readonly int $timeout = 10,
        private readonly ?string $forcedUrl = null,
    ) {}

    /** @return array{der: string, produced_at: ?int, status: string, responder_certificate: ?string} */
    public function check(Certificate $subject, Certificate $issuer): array
    {
        $url = $this->forcedUrl ?? $subject->ocspUrl();

        if ($url === null) {
            throw new RuntimeException('The certificate names no OCSP responder and none was configured.');
        }

        $request = $this->request($subject, $issuer);
        $response = $this->post($url, $request);
        $parsed = $this->parse($response);

        if ($parsed['status'] === 'revoked') {
            throw new RuntimeException('The signing certificate is revoked; the signature cannot be completed.');
        }

        return $parsed + ['der' => $response];
    }

    /** OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest } — one CertID, with a nonce. */
    public function request(Certificate $subject, Certificate $issuer): string
    {
        $certId = Der::sequence(
            Der::sequence(Der::oid('1.3.14.3.2.26'), Der::null()),          // SHA-1, as the CertID mandates
            Der::octetString(sha1($subject->issuerNameDer(), true)),
            Der::octetString(Certificate::keyHash($issuer)),
            Der::integerFromBytes($subject->serialBytes()),
        );

        $nonce = random_bytes(20);
        $extensions = Der::context(2, Der::sequence(
            Der::sequence(Der::oid('1.3.6.1.5.5.7.48.1.2'), Der::octetString(Der::octetString($nonce))),
        ));

        $tbs = Der::sequence(
            Der::sequence(Der::sequence($certId)),
            $extensions,
        );

        return Der::sequence($tbs);
    }

    /** @return array{produced_at: ?int, status: string, responder_certificate: ?string} */
    public function parse(string $der): array
    {
        $responseStatus = Der::find($der, [0]);

        if ($responseStatus === null || $responseStatus['value'] !== "\x00") {
            throw new RuntimeException('The OCSP responder refused the request (status '.bin2hex($responseStatus['value'] ?? '').').');
        }

        $basic = Der::find($der, [1, 0, 1]);

        if ($basic === null) {
            throw new RuntimeException('The OCSP answer has no basic response.');
        }

        $basicResponse = Der::read($basic['value']);
        $tbs = Der::children($basicResponse['value'])[0] ?? throw new RuntimeException('Malformed OCSP answer.');
        $fields = Der::children($tbs['value']);

        $producedAt = null;
        $status = 'unknown';
        $responderCertificate = null;

        foreach ($fields as $field) {
            if ($field['tag'] === Der::GENERALIZED_TIME && $producedAt === null) {
                $producedAt = strtotime(rtrim($field['value'], 'Z').' UTC') ?: null;
            }

            if ($field['tag'] === Der::SEQUENCE) {
                foreach (Der::children($field['value']) as $single) {
                    foreach (Der::children($single['value']) as $part) {
                        if ($part['tag'] === 0x80) {
                            $status = 'good';
                        } elseif ($part['tag'] === 0xA1) {
                            $status = 'revoked';
                        } elseif ($part['tag'] === 0x82) {
                            $status = 'unknown';
                        }
                    }
                }
            }

            if ($field['tag'] === 0xA0) {
                $certs = Der::read($field['value']);
                $first = Der::children($certs['value'])[0] ?? null;
                $responderCertificate = $first !== null ? base64_encode($first['raw']) : null;
            }
        }

        return ['produced_at' => $producedAt, 'status' => $status, 'responder_certificate' => $responderCertificate];
    }

    private function post(string $url, string $body): string
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/ocsp-request\r\nAccept: application/ocsp-response\r\n",
                'content' => $body,
                'timeout' => $this->timeout,
                'ignore_errors' => true,
            ],
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false || $response === '') {
            throw new RuntimeException("The OCSP responder at {$url} did not answer.");
        }

        return $response;
    }
}
