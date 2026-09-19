<?php

declare(strict_types=1);

namespace Komma\Asice\Signature;

use DOMDocument;
use DOMElement;
use DOMXPath;
use Komma\Asice\Crypto\C14n;
use Komma\Asice\Crypto\Certificate;
use Komma\Asice\Crypto\SignAlg;
use RuntimeException;

/**
 * Builds the XAdES signature document of an ASiC-E container: one Reference
 * per data file, one for the signed properties, and — once the signature
 * value is in — the OCSP answer and the time-stamp that make it long-term.
 *
 * The signature is produced in two halves on purpose: the hash comes out,
 * the card or the phone signs it somewhere else, the value comes back.
 */
final class XadesSignature
{
    public const DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    public const XADES = 'http://uri.etsi.org/01903/v1.3.2#';

    public const XADES141 = 'http://uri.etsi.org/01903/v1.4.1#';

    public const ASIC = 'http://uri.etsi.org/02918/v1.2.1#';

    private DOMDocument $document;

    private string $signatureId;

    /**
     * @param  array<string, array{mime: string, content: string}>  $files
     */
    public function __construct(
        private readonly Certificate $certificate,
        private readonly array $files,
        private readonly SignAlg $alg = SignAlg::SHA256,
        private readonly ?string $city = null,
        private readonly ?string $country = null,
        private readonly array $roles = [],
    ) {
        $this->signatureId = 'S'.substr(bin2hex(random_bytes(6)), 0, 8);
        $this->document = $this->build();
    }

    public function id(): string
    {
        return $this->signatureId;
    }

    public function document(): DOMDocument
    {
        return $this->document;
    }

    public function xml(): string
    {
        return $this->document->saveXML();
    }

    public static function fromXml(string $xml, Certificate $certificate, SignAlg $alg = SignAlg::SHA256): self
    {
        $instance = new self($certificate, [], $alg);
        $document = new DOMDocument('1.0', 'UTF-8');
        $document->loadXML($xml);
        $instance->document = $document;
        $instance->signatureId = (string) $document->getElementsByTagNameNS(self::DSIG, 'Signature')->item(0)?->getAttribute('Id');

        return $instance;
    }

    /** The canonical SignedInfo — the bytes the signature is computed over. */
    public function canonicalSignedInfo(): string
    {
        return C14n::node($this->element('SignedInfo'));
    }

    /** The digest the card, Smart-ID or Mobile-ID is asked to sign. */
    public function dataToSign(): string
    {
        return $this->alg->digest($this->canonicalSignedInfo());
    }

    public function setSignatureValue(string $rawSignature): void
    {
        $node = $this->element('SignatureValue');
        $node->nodeValue = base64_encode($rawSignature);
    }

    public function signatureValue(): string
    {
        return base64_decode(preg_replace('/\s+/', '', $this->element('SignatureValue')->textContent) ?? '', true) ?: '';
    }

    /**
     * Adds the unsigned properties that make the signature long-term: the
     * time-stamp over the signature value and the OCSP answer for the
     * signer's certificate, with the certificates they reference.
     */
    public function addUnsignedProperties(?array $timestamp, ?array $ocsp, ?Certificate $issuer): void
    {
        $qualifying = $this->element('QualifyingProperties');
        $unsigned = $this->document->createElementNS(self::XADES, 'xades:UnsignedProperties');
        $unsigned->setAttribute('Id', $this->signatureId.'-UP');
        $signatureProperties = $this->document->createElementNS(self::XADES, 'xades:UnsignedSignatureProperties');
        $unsigned->appendChild($signatureProperties);

        if ($timestamp !== null) {
            $sigTimestamp = $this->document->createElementNS(self::XADES, 'xades:SignatureTimeStamp');
            $sigTimestamp->setAttribute('Id', $this->signatureId.'-T0');
            $canon = $this->document->createElementNS(self::DSIG, 'ds:CanonicalizationMethod');
            $canon->setAttribute('Algorithm', C14n::METHOD);
            $sigTimestamp->appendChild($canon);
            $encapsulated = $this->document->createElementNS(self::XADES, 'xades:EncapsulatedTimeStamp', base64_encode($timestamp['der']));
            $encapsulated->setAttribute('Id', $this->signatureId.'-TS');
            $sigTimestamp->appendChild($encapsulated);
            $signatureProperties->appendChild($sigTimestamp);
        }

        if ($ocsp !== null || $issuer !== null) {
            $values = $this->document->createElementNS(self::XADES, 'xades:CertificateValues');

            if ($issuer !== null) {
                $certificate = $this->document->createElementNS(self::XADES, 'xades:EncapsulatedX509Certificate', $issuer->base64());
                $certificate->setAttribute('Id', $this->signatureId.'-CA');
                $values->appendChild($certificate);
            }

            if (($ocsp['responder_certificate'] ?? null) !== null) {
                $responder = $this->document->createElementNS(self::XADES, 'xades:EncapsulatedX509Certificate', $ocsp['responder_certificate']);
                $responder->setAttribute('Id', $this->signatureId.'-RESPONDER');
                $values->appendChild($responder);
            }

            if ($values->hasChildNodes()) {
                $signatureProperties->appendChild($values);
            }
        }

        if ($ocsp !== null) {
            $revocation = $this->document->createElementNS(self::XADES, 'xades:RevocationValues');
            $ocspValues = $this->document->createElementNS(self::XADES, 'xades:OCSPValues');
            $encapsulated = $this->document->createElementNS(self::XADES, 'xades:EncapsulatedOCSPValue', base64_encode($ocsp['der']));
            $encapsulated->setAttribute('Id', $this->signatureId.'-OCSP');
            $ocspValues->appendChild($encapsulated);
            $revocation->appendChild($ocspValues);
            $signatureProperties->appendChild($revocation);
        }

        $qualifying->appendChild($unsigned);
    }

    /** @return array<string, array{mime: string, digest: string}> */
    public function references(): array
    {
        $out = [];
        $xpath = new DOMXPath($this->document);
        $xpath->registerNamespace('ds', self::DSIG);

        foreach ($xpath->query('//ds:SignedInfo/ds:Reference') as $reference) {
            /** @var DOMElement $reference */
            $uri = rawurldecode((string) $reference->getAttribute('URI'));

            if (str_starts_with($uri, '#')) {
                continue;
            }

            $digest = $xpath->query('ds:DigestValue', $reference)->item(0)?->textContent ?? '';
            $out[$uri] = ['mime' => (string) $reference->getAttribute('Type'), 'digest' => trim($digest)];
        }

        return $out;
    }

    public function signingTime(): ?int
    {
        $node = $this->document->getElementsByTagNameNS(self::XADES, 'SigningTime')->item(0);

        return $node !== null ? (strtotime($node->textContent) ?: null) : null;
    }

    public function signerCertificate(): ?Certificate
    {
        $node = $this->document->getElementsByTagNameNS(self::DSIG, 'X509Certificate')->item(0);

        return $node !== null ? Certificate::fromBase64($node->textContent) : null;
    }

    /** Verifies SignedInfo against the signature value with the signer's public key. */
    public function verify(): bool
    {
        $certificate = $this->signerCertificate();

        if ($certificate === null) {
            return false;
        }

        $key = openssl_pkey_get_public($certificate->pem);

        if ($key === false) {
            return false;
        }

        $signedInfo = C14n::node($this->element('SignedInfo'));
        $signature = $this->signatureValue();

        if ($certificate->keyType() === 'EC') {
            $signature = self::ecdsaToDer($signature);
        }

        return openssl_verify($signedInfo, $signature, $key, $this->alg->hashAlgorithm()) === 1;
    }

    /** Raw r‖s from a card into the DER SEQUENCE openssl_verify expects. */
    public static function ecdsaToDer(string $raw): string
    {
        $half = intdiv(strlen($raw), 2);
        $r = ltrim(substr($raw, 0, $half), "\x00");
        $s = ltrim(substr($raw, $half), "\x00");
        $int = static fn (string $v): string => "\x02".chr(strlen($v) + (ord($v[0]) > 0x7F ? 1 : 0)).(ord($v[0]) > 0x7F ? "\x00" : '').$v;
        $body = $int($r).$int($s);

        return "\x30".chr(strlen($body)).$body;
    }

    private function element(string $localName): DOMElement
    {
        $node = $this->document->getElementsByTagNameNS(self::DSIG, $localName)->item(0)
            ?? $this->document->getElementsByTagNameNS(self::XADES, $localName)->item(0);

        if (! $node instanceof DOMElement) {
            throw new RuntimeException("The signature has no {$localName} element.");
        }

        return $node;
    }

    private function build(): DOMDocument
    {
        $document = new DOMDocument('1.0', 'UTF-8');
        $document->formatOutput = false;

        $root = $document->createElementNS(self::ASIC, 'asic:XAdESSignatures');
        $root->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', self::DSIG);
        $root->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:xades', self::XADES);
        $document->appendChild($root);

        $signature = $document->createElementNS(self::DSIG, 'ds:Signature');
        $signature->setAttribute('Id', $this->signatureId);
        $root->appendChild($signature);

        $signedInfo = $document->createElementNS(self::DSIG, 'ds:SignedInfo');
        $signature->appendChild($signedInfo);

        $canon = $document->createElementNS(self::DSIG, 'ds:CanonicalizationMethod');
        $canon->setAttribute('Algorithm', C14n::METHOD);
        $signedInfo->appendChild($canon);

        $method = $document->createElementNS(self::DSIG, 'ds:SignatureMethod');
        $method->setAttribute('Algorithm', $this->alg->signatureMethodUri($this->certificate->keyType()));
        $signedInfo->appendChild($method);

        foreach ($this->files as $name => $file) {
            $reference = $document->createElementNS(self::DSIG, 'ds:Reference');
            $reference->setAttribute('Id', $this->signatureId.'-REF-'.count($signedInfo->childNodes));
            $reference->setAttribute('URI', rawurlencode($name));
            $reference->setAttribute('Type', $file['mime']);
            $digestMethod = $document->createElementNS(self::DSIG, 'ds:DigestMethod');
            $digestMethod->setAttribute('Algorithm', $this->alg->digestMethodUri());
            $reference->appendChild($digestMethod);
            $reference->appendChild($document->createElementNS(self::DSIG, 'ds:DigestValue', base64_encode($this->alg->digest($file['content']))));
            $signedInfo->appendChild($reference);
        }

        $signatureValue = $document->createElementNS(self::DSIG, 'ds:SignatureValue', '');
        $signatureValue->setAttribute('Id', $this->signatureId.'-SIG');
        $signature->appendChild($signatureValue);

        $keyInfo = $document->createElementNS(self::DSIG, 'ds:KeyInfo');
        $keyInfo->setAttribute('Id', $this->signatureId.'-KEYINFO');
        $x509Data = $document->createElementNS(self::DSIG, 'ds:X509Data');
        $x509Data->appendChild($document->createElementNS(self::DSIG, 'ds:X509Certificate', $this->certificate->base64()));
        $keyInfo->appendChild($x509Data);
        $signature->appendChild($keyInfo);

        $object = $document->createElementNS(self::DSIG, 'ds:Object');
        $qualifying = $document->createElementNS(self::XADES, 'xades:QualifyingProperties');
        $qualifying->setAttribute('Target', '#'.$this->signatureId);
        $object->appendChild($qualifying);
        $signature->appendChild($object);

        $signedProperties = $document->createElementNS(self::XADES, 'xades:SignedProperties');
        $signedProperties->setAttribute('Id', $this->signatureId.'-SignedProperties');
        $qualifying->appendChild($signedProperties);

        $signatureProperties = $document->createElementNS(self::XADES, 'xades:SignedSignatureProperties');
        $signedProperties->appendChild($signatureProperties);
        $signatureProperties->appendChild($document->createElementNS(self::XADES, 'xades:SigningTime', gmdate('Y-m-d\TH:i:s\Z')));

        $signingCertificate = $document->createElementNS(self::XADES, 'xades:SigningCertificateV2');
        $cert = $document->createElementNS(self::XADES, 'xades:Cert');
        $certDigest = $document->createElementNS(self::XADES, 'xades:CertDigest');
        $digestMethod = $document->createElementNS(self::DSIG, 'ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', $this->alg->digestMethodUri());
        $certDigest->appendChild($digestMethod);
        $certDigest->appendChild($document->createElementNS(self::DSIG, 'ds:DigestValue', base64_encode($this->certificate->digest($this->alg))));
        $cert->appendChild($certDigest);
        $signingCertificate->appendChild($cert);
        $signatureProperties->appendChild($signingCertificate);

        if ($this->city !== null || $this->country !== null) {
            $production = $document->createElementNS(self::XADES, 'xades:SignatureProductionPlaceV2');

            if ($this->city !== null) {
                $production->appendChild($document->createElementNS(self::XADES, 'xades:City', $this->city));
            }

            if ($this->country !== null) {
                $production->appendChild($document->createElementNS(self::XADES, 'xades:CountryName', $this->country));
            }

            $signatureProperties->appendChild($production);
        }

        if ($this->roles !== []) {
            $rolesNode = $document->createElementNS(self::XADES, 'xades:SignerRoleV2');
            $claimed = $document->createElementNS(self::XADES, 'xades:ClaimedRoles');

            foreach ($this->roles as $role) {
                $claimed->appendChild($document->createElementNS(self::XADES, 'xades:ClaimedRole', (string) $role));
            }

            $rolesNode->appendChild($claimed);
            $signatureProperties->appendChild($rolesNode);
        }

        $dataObject = $document->createElementNS(self::XADES, 'xades:SignedDataObjectProperties');
        $signedProperties->appendChild($dataObject);

        // The reference over SignedProperties closes the loop: what the card
        // signs covers both the files and the properties about the signature.
        $reference = $document->createElementNS(self::DSIG, 'ds:Reference');
        $reference->setAttribute('Id', $this->signatureId.'-REF-SP');
        $reference->setAttribute('Type', 'http://uri.etsi.org/01903#SignedProperties');
        $reference->setAttribute('URI', '#'.$this->signatureId.'-SignedProperties');
        $transforms = $document->createElementNS(self::DSIG, 'ds:Transforms');
        $transform = $document->createElementNS(self::DSIG, 'ds:Transform');
        $transform->setAttribute('Algorithm', C14n::METHOD);
        $transforms->appendChild($transform);
        $reference->appendChild($transforms);
        $digestMethod = $document->createElementNS(self::DSIG, 'ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', $this->alg->digestMethodUri());
        $reference->appendChild($digestMethod);
        $reference->appendChild($document->createElementNS(self::DSIG, 'ds:DigestValue', base64_encode($this->alg->digest(C14n::node($signedProperties)))));
        $signedInfo->appendChild($reference);

        return $document;
    }
}