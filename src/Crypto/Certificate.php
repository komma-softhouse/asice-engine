<?php

declare(strict_types=1);

namespace Komma\Asice\Crypto;

use Komma\Asice\Asn1\Der;
use RuntimeException;

/**
 * A signing certificate, read for what the signature needs: who signed
 * (name, personal code), the issuer's name and public key hashed the way
 * OCSP wants them, the serial number, and where to ask about revocation.
 */
final class Certificate
{
    private array $parsed;

    private function __construct(
        public readonly string $der,
        public readonly string $pem,
    ) {
        $info = openssl_x509_parse($this->pem, false);

        if ($info === false) {
            throw new RuntimeException('The certificate could not be parsed.');
        }

        $this->parsed = $info;
    }

    public static function fromBase64(string $base64): self
    {
        $der = base64_decode(preg_replace('/\s+|-----[A-Z ]+-----/', '', $base64) ?? '', true);

        if ($der === false || $der === '') {
            throw new RuntimeException('The certificate is not valid base64.');
        }

        return self::fromDer($der);
    }

    public static function fromDer(string $der): self
    {
        return new self($der, "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n").'-----END CERTIFICATE-----');
    }

    public static function fromPem(string $pem): self
    {
        $der = base64_decode(preg_replace('/\s+|-----[A-Z ]+-----/', '', $pem) ?? '', true);

        if ($der === false) {
            throw new RuntimeException('The certificate is not valid PEM.');
        }

        return new self($der, $pem);
    }

    public function base64(): string
    {
        return base64_encode($this->der);
    }

    public function digest(SignAlg $alg): string
    {
        return $alg->digest($this->der);
    }

    /** The subject as one line, the way DigiDoc prints it. */
    public function subject(): string
    {
        $subject = (array) ($this->parsed['subject'] ?? []);
        $parts = [];

        foreach (['CN' => 'CN', 'SN' => 'SN', 'GN' => 'GN', 'serialNumber' => 'serialNumber', 'O' => 'O', 'C' => 'C'] as $key => $label) {
            if (isset($subject[$key])) {
                $parts[] = $label.'='.(is_array($subject[$key]) ? implode(',', $subject[$key]) : $subject[$key]);
            }
        }

        return implode(', ', $parts);
    }

    public function issuerName(): string
    {
        $issuer = (array) ($this->parsed['issuer'] ?? []);
        $parts = [];

        foreach (array_reverse($issuer) as $key => $value) {
            $parts[] = $key.'='.(is_array($value) ? implode(',', $value) : $value);
        }

        return implode(',', $parts);
    }

    /** The signer's display name: "SURNAME, GIVEN NAME" as the CN carries it. */
    public function signerName(): string
    {
        $subject = (array) ($this->parsed['subject'] ?? []);
        $surname = $subject['SN'] ?? $subject['surname'] ?? null;
        $given = $subject['GN'] ?? $subject['givenName'] ?? null;

        if ($surname && $given) {
            return trim((string) $given).' '.trim((string) $surname);
        }

        $cn = (string) ($subject['CN'] ?? '');
        $pieces = array_map('trim', explode(',', $cn));

        return count($pieces) >= 2 ? $pieces[1].' '.$pieces[0] : $cn;
    }

    /** Estonian personal identification code from the subject serial number (PNOEE-…). */
    public function personalCode(): ?string
    {
        $subject = (array) ($this->parsed['subject'] ?? []);
        $serial = (string) ($subject['serialNumber'] ?? '');

        if ($serial === '') {
            $cn = (string) ($subject['CN'] ?? '');
            $pieces = array_map('trim', explode(',', $cn));
            $serial = $pieces[2] ?? '';
        }

        if (preg_match('/(\d{11})/', $serial, $m) === 1) {
            return $m[1];
        }

        return null;
    }

    /** Serial number as raw big-endian bytes, for the OCSP CertID. */
    public function serialBytes(): string
    {
        $node = Der::find($this->der, [0, 0]);

        // [0] is the optional explicit version tag; the serial follows it.
        if ($node !== null && $node['tag'] === 0xA0) {
            $node = Der::find($this->der, [0, 1]);
        }

        if ($node === null) {
            throw new RuntimeException('The certificate has no readable serial number.');
        }

        return ltrim($node['value'], "\x00") ?: "\x00";
    }

    public function serialHex(): string
    {
        return strtoupper(bin2hex($this->serialBytes()));
    }

    /** The issuer's distinguished name, DER-encoded, hashed for the OCSP CertID. */
    public function issuerNameDer(): string
    {
        $tbs = Der::find($this->der, [0]);

        if ($tbs === null) {
            throw new RuntimeException('The certificate has no readable body.');
        }

        $children = Der::children($tbs['value']);
        $index = ($children[0]['tag'] ?? 0) === 0xA0 ? 3 : 2;

        return $children[$index]['raw'] ?? throw new RuntimeException('The certificate has no readable issuer.');
    }

    public function notBefore(): ?int
    {
        return isset($this->parsed['validFrom_time_t']) ? (int) $this->parsed['validFrom_time_t'] : null;
    }

    public function notAfter(): ?int
    {
        return isset($this->parsed['validTo_time_t']) ? (int) $this->parsed['validTo_time_t'] : null;
    }

    public function keyType(): string
    {
        $key = openssl_pkey_get_public($this->pem);

        if ($key === false) {
            return 'RSA';
        }

        return (openssl_pkey_get_details($key)['type'] ?? OPENSSL_KEYTYPE_RSA) === OPENSSL_KEYTYPE_EC ? 'EC' : 'RSA';
    }

    /** OCSP responder URL from the Authority Information Access extension. */
    public function ocspUrl(): ?string
    {
        $aia = (string) ($this->parsed['extensions']['authorityInfoAccess'] ?? '');

        if (preg_match('/OCSP - URI:(\S+)/', $aia, $m) === 1) {
            return $m[1];
        }

        return null;
    }

    /** Where the issuer's own certificate can be fetched, when the chain is not at hand. */
    public function issuerUrl(): ?string
    {
        $aia = (string) ($this->parsed['extensions']['authorityInfoAccess'] ?? '');

        if (preg_match('/CA Issuers - URI:(\S+)/', $aia, $m) === 1) {
            return $m[1];
        }

        return null;
    }

    /** SHA-1 of the issuer's public key bits, as the OCSP CertID requires. */
    public static function keyHash(self $issuer): string
    {
        $tbs = Der::find($issuer->der, [0]);
        $children = Der::children($tbs['value'] ?? '');
        $offset = ($children[0]['tag'] ?? 0) === 0xA0 ? 1 : 0;
        $spki = $children[5 + $offset] ?? null;

        if ($spki === null) {
            throw new RuntimeException('The issuer certificate has no readable public key.');
        }

        $bitString = Der::children($spki['value'])[1] ?? throw new RuntimeException('Malformed public key.');

        // The BIT STRING body starts with the count of unused bits.
        return sha1(substr($bitString['value'], 1), true);
    }
}
