# ASiC-E engine

ASiC-E containers with XAdES signatures for Estonian eID. Hash in, container out: the engine builds the container and the signature document, hands you the digest to sign, and finishes the job when the value comes back — from an ID-kaart through Web eID, from Smart-ID or from Mobile-ID. It then fetches the OCSP answer and the time-stamp that make the signature long-term.

Used by `komma-softhouse/filament-eesti-billing`; usable on its own in any PHP application.

## Requirements

PHP 8.3+, `ext-openssl`, `ext-zip`, `ext-dom`. No other dependency.

## Installation

```bash
composer require komma-softhouse/asice-engine
```

## Signing

```php
use Komma\Asice\Container\UnsignedContainer;
use Komma\Asice\Crypto\SignAlg;

$container = UnsignedContainer::make()
    ->addFile('invoice.pdf', $pdf, 'application/pdf')
    ->addFile('invoice.xml', $xml, 'application/xml')
    ->build('/tmp/invoice.asice');

$pending = $container->createSignature($certificateBase64, SignAlg::SHA256, city: 'Tallinn', country: 'EE');

$hash = $pending->getHashBase64();   // what the card or the phone signs
$state = $pending->serialize();      // survives a session, a queue or a database row
```

Then, once the signature value is back:

```php
use Komma\Asice\Container\Container;
use Komma\Asice\Signature\PendingSignature;

$container = Container::open('/tmp/invoice.asice');
$result = $container->finishSignature(PendingSignature::unserialize($state), $signatureValue);
$container->save();

$result['long_term'];   // true when both the time-stamp and the OCSP answer were obtained
$result['notes'];       // what could not be reached, if anything
```

The signature value is verified against the hash before anything is written: a wrong value never lands in the container. A revoked certificate stops the process.

## Validating

```php
$result = Container::open($path)->validate();

$result->isValid();

foreach ($result->signatures() as $signer) {
    $signer->name();          // "TESTPERE TESTNIMI"
    $signer->personalCode();  // "38001085718"
    $signer->signedAt();      // DateTimeImmutable
    $signer->isLongTerm();    // time-stamp + OCSP answer present
    $signer->errors();
}
```

Validation recomputes every file digest against its Reference, so a file changed after signing is reported by name.

## Services

By default the engine asks the OCSP responder named in the signer's certificate (SK's public AIA responder for Estonian eID) and `http://tsa.sk.ee` for the time-stamp. Point them elsewhere, or hand the issuer certificate over when you already have the chain:

```php
use Komma\Asice\Ocsp\OcspClient;
use Komma\Asice\Tsa\TimestampClient;

$container->using(
    ocsp: new OcspClient(timeout: 15),
    tsa: new TimestampClient('http://tsa.example.org'),
    issuer: $issuerCertificate,
);
```

If either service cannot be reached, the container is still written with a valid basic signature and `notes` explains what is missing.

## Several signers

`createSignature()` can run again on a saved container; each finished signature becomes its own `META-INF/signatures{n}.xml`. The data files are untouched.

## What is in the container

`mimetype` (stored, first), `META-INF/manifest.xml`, the data files, and one `META-INF/signatures{n}.xml` per signature holding the XAdES structure: a Reference per file, the signed properties with the signing time and the certificate digest, the signature value, and the unsigned properties with the time-stamp and the OCSP answer.

## Testing

```bash
composer install
vendor/bin/pest
```

The suite signs with a throwaway key pair, so it runs offline; only the time-stamp and OCSP steps need a network, and their absence is a note, not a failure.

## Security

If you discover a security issue, email info@kommasofthouse.com instead of using the issue tracker.

## License

Commercial. See `LICENSE.md`.
