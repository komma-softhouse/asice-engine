<?php

declare(strict_types=1);

use Komma\Asice\Container\Container;
use Komma\Asice\Container\Manifest;
use Komma\Asice\Container\UnsignedContainer;
use Komma\Asice\Crypto\SignAlg;
use Komma\Asice\Signature\PendingSignature;

/** A throwaway key pair, standing in for the card. */
function signer(): array
{
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $csr = openssl_csr_new(['commonName' => 'TESTNIMI,TESTPERE,38001085718', 'surname' => 'TESTNIMI', 'givenName' => 'TESTPERE', 'serialNumber' => 'PNOEE-38001085718', 'countryName' => 'EE'], $key, ['digest_alg' => 'sha256']);
    $cert = openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256']);
    openssl_x509_export($cert, $pem);

    return [$key, trim(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r"], '', $pem))];
}

function sign(Container $container, PendingSignature $pending, $key): array
{
    openssl_sign($pending->signature->canonicalSignedInfo(), $signature, $key, OPENSSL_ALGO_SHA256);

    return $container->finishSignature($pending, $signature);
}

it('builds a container whose first entry is the stored mimetype', function () {
    $path = tempnam(sys_get_temp_dir(), 'asice-').'.asice';
    UnsignedContainer::make()->addFile('invoice.pdf', '%PDF-1.4 test', 'application/pdf')->build($path);

    $zip = new ZipArchive;
    $zip->open($path);

    expect($zip->getNameIndex(0))->toBe('mimetype')
        ->and($zip->getFromName('mimetype'))->toBe('application/vnd.etsi.asic-e+zip')
        ->and($zip->statName('mimetype')['comp_method'])->toBe(ZipArchive::CM_STORE)
        ->and(Manifest::parse((string) $zip->getFromName('META-INF/manifest.xml')))->toBe(['invoice.pdf' => 'application/pdf']);

    $zip->close();
    unlink($path);
});

it('signs, stores the signature and reads the signer back', function () {
    [$key, $certificate] = signer();
    $path = tempnam(sys_get_temp_dir(), 'asice-').'.asice';

    $container = UnsignedContainer::make()
        ->addFile('invoice.pdf', '%PDF-1.4 test', 'application/pdf')
        ->addFile('invoice.xml', '<Invoice/>', 'application/xml')
        ->build($path);

    $pending = $container->createSignature($certificate, SignAlg::SHA256, city: 'Tallinn', country: 'EE');
    expect(strlen($pending->getHash()))->toBe(32);

    sign($container, $pending, $key);
    $container->save($path);

    $result = Container::open($path)->validate();
    $signer = $result->signatures()[0];

    expect($result->isValid())->toBeTrue()
        ->and($result->signatures())->toHaveCount(1)
        ->and($signer->personalCode())->toBe('38001085718')
        ->and($signer->name())->toContain('TEST')
        ->and($signer->signedAt()->getTimestamp())->toBeGreaterThan(time() - 60);

    unlink($path);
});

it('refuses a signature value that does not match the hash', function () {
    [$key, $certificate] = signer();
    $container = UnsignedContainer::make()->addFile('a.txt', 'hello', 'text/plain')->build();
    $pending = $container->createSignature($certificate);

    expect(fn () => $container->finishSignature($pending, str_repeat("\x00", 256)))->toThrow(RuntimeException::class);
});

it('detects a file changed after signing', function () {
    [$key, $certificate] = signer();
    $path = tempnam(sys_get_temp_dir(), 'asice-').'.asice';

    $container = UnsignedContainer::make()->addFile('a.txt', 'hello', 'text/plain')->build($path);
    sign($container, $container->createSignature($certificate), $key);
    $container->save($path);

    $zip = new ZipArchive;
    $zip->open($path);
    $zip->addFromString('a.txt', 'tampered');
    $zip->close();

    $result = Container::open($path)->validate();

    expect($result->isValid())->toBeFalse()
        ->and($result->signatures()[0]->errors()[0])->toContain('changed after it was signed');

    unlink($path);
});

it('carries a pending signature through serialization', function () {
    [$key, $certificate] = signer();
    $container = UnsignedContainer::make()->addFile('a.txt', 'hello', 'text/plain')->build();
    $pending = $container->createSignature($certificate);

    $restored = PendingSignature::unserialize($pending->serialize());

    expect($restored->getHash())->toBe($pending->getHash())
        ->and($restored->signature->canonicalSignedInfo())->toBe($pending->signature->canonicalSignedInfo());
});

it('takes a second signature on the same container', function () {
    [$key, $certificate] = signer();
    $path = tempnam(sys_get_temp_dir(), 'asice-').'.asice';
    $container = UnsignedContainer::make()->addFile('a.txt', 'hello', 'text/plain')->build($path);

    sign($container, $container->createSignature($certificate), $key);
    sign($container, $container->createSignature($certificate), $key);
    $container->save($path);

    expect(Container::open($path)->signatureCount())->toBe(2);

    unlink($path);
});
