<?php

declare(strict_types=1);

namespace Komma\Asice\Container;

use DateTimeImmutable;
use Komma\Asice\Crypto\Certificate;
use Komma\Asice\Crypto\SignAlg;
use Komma\Asice\Ocsp\OcspClient;
use Komma\Asice\Signature\PendingSignature;
use Komma\Asice\Signature\XadesSignature;
use Komma\Asice\Tsa\TimestampClient;
use Komma\Asice\Validation\SignerInfo;
use Komma\Asice\Validation\ValidationResult;
use RuntimeException;
use Throwable;
use ZipArchive;

/**
 * An ASiC-E container (.asice / .bdoc): a ZIP whose first entry is an
 * uncompressed `mimetype`, a `META-INF/manifest.xml` describing the payload,
 * the data files themselves, and one `META-INF/signatures*.xml` per
 * signature.
 *
 *     $container = UnsignedContainer::make()
 *         ->addFile('invoice.pdf', $pdf, 'application/pdf')
 *         ->build('/tmp/invoice.asice');
 *
 *     $pending = $container->createSignature($certificateBase64);
 *     // … the card, Smart-ID or Mobile-ID signs $pending->getHash() …
 *     $container->finishSignature($pending, $signatureValue);
 *     $container->save('/tmp/invoice.asice');
 */
final class Container
{
    public const MIMETYPE = 'application/vnd.etsi.asic-e+zip';

    /** @var array<string, array{mime: string, content: string}> */
    private array $files = [];

    /** @var array<string, string> name => signature XML */
    private array $signatures = [];

    private function __construct(
        private ?string $path = null,
        private ?OcspClient $ocsp = null,
        private ?TimestampClient $tsa = null,
        private ?Certificate $issuer = null,
    ) {
        $this->ocsp ??= new OcspClient;
        $this->tsa ??= new TimestampClient;
    }

    /** @param array<string, array{mime: string, content: string}> $files */
    public static function fromFiles(array $files, ?string $path = null): self
    {
        $container = new self($path);
        $container->files = $files;

        return $container;
    }

    public static function open(string $path): self
    {
        $zip = new ZipArchive;

        if ($zip->open($path) !== true) {
            throw new RuntimeException("The container at {$path} could not be opened.");
        }

        $container = new self($path);
        $manifest = Manifest::parse((string) $zip->getFromName('META-INF/manifest.xml'));

        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = (string) $zip->getNameIndex($i);

            if ($name === 'mimetype' || str_ends_with($name, '/')) {
                continue;
            }

            $content = (string) $zip->getFromIndex($i);

            if (str_starts_with($name, 'META-INF/')) {
                if (preg_match('#^META-INF/.*signatures.*\.xml$#i', $name) === 1) {
                    $container->signatures[$name] = $content;
                }

                continue;
            }

            $container->files[$name] = ['mime' => $manifest[$name] ?? 'application/octet-stream', 'content' => $content];
        }

        $zip->close();

        return $container;
    }

    /** Where the revocation and time-stamp services live, and the issuer chain when it is at hand. */
    public function using(?OcspClient $ocsp = null, ?TimestampClient $tsa = null, ?Certificate $issuer = null): self
    {
        $this->ocsp = $ocsp ?? $this->ocsp;
        $this->tsa = $tsa ?? $this->tsa;
        $this->issuer = $issuer ?? $this->issuer;

        return $this;
    }

    /** @return array<string, array{mime: string, content: string}> */
    public function files(): array
    {
        return $this->files;
    }

    public function file(string $name): ?string
    {
        return $this->files[$name]['content'] ?? null;
    }

    public function signatureCount(): int
    {
        return count($this->signatures);
    }

    /**
     * Step one: the hash to sign. Nothing is written yet — a signature that
     * is never finished leaves no trace in the container.
     */
    public function createSignature(string $certificateBase64, SignAlg $alg = SignAlg::SHA256, ?string $city = null, ?string $country = null, array $roles = []): PendingSignature
    {
        if ($this->files === []) {
            throw new RuntimeException('A container with no files cannot be signed.');
        }

        $certificate = Certificate::fromBase64($certificateBase64);
        $signature = new XadesSignature($certificate, $this->files, $alg, $city, $country, $roles);

        return new PendingSignature($signature, $certificate, $alg, $signature->dataToSign());
    }

    /**
     * Step two: the value comes back from the card or the phone. The
     * signature is verified before anything is stored, then the time-stamp
     * and the OCSP answer are fetched so the result stands on its own.
     * Either service being down leaves a valid basic signature and says so.
     *
     * @return array{long_term: bool, notes: list<string>}
     */
    public function finishSignature(PendingSignature $pending, string $signatureValue): array
    {
        $signature = $pending->signature;
        $signature->setSignatureValue($signatureValue);

        if (! $signature->verify()) {
            throw new RuntimeException('The signature value does not match the hash that was handed out.');
        }

        $notes = [];
        $timestamp = null;
        $ocsp = null;

        try {
            $timestamp = $this->tsa->stamp($signature->signatureValue(), $pending->alg);
        } catch (Throwable $e) {
            $notes[] = 'No time-stamp: '.$e->getMessage();
        }

        $issuer = $this->issuer ?? $this->fetchIssuer($pending->certificate);

        if ($issuer !== null) {
            try {
                $ocsp = $this->ocsp->check($pending->certificate, $issuer);
            } catch (Throwable $e) {
                if (str_contains($e->getMessage(), 'revoked')) {
                    throw $e;
                }

                $notes[] = 'No revocation answer: '.$e->getMessage();
            }
        } else {
            $notes[] = 'No revocation answer: the issuer certificate could not be obtained.';
        }

        $signature->addUnsignedProperties($timestamp, $ocsp, $issuer);

        $index = count($this->signatures);
        $this->signatures["META-INF/signatures{$index}.xml"] = $signature->xml();

        return ['long_term' => $timestamp !== null && $ocsp !== null, 'notes' => $notes];
    }

    public function save(?string $path = null): string
    {
        $path = $path ?? $this->path ?? throw new RuntimeException('No path to save the container to.');
        $temporary = $path.'.tmp';
        @unlink($temporary);

        $zip = new ZipArchive;

        if ($zip->open($temporary, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new RuntimeException("The container at {$path} could not be written.");
        }

        // The mimetype entry must come first and be stored, not deflated:
        // that is what lets a reader identify the format from the first bytes.
        $zip->addFromString('mimetype', self::MIMETYPE);
        $zip->setCompressionName('mimetype', ZipArchive::CM_STORE);

        $zip->addFromString('META-INF/manifest.xml', Manifest::build($this->files));

        foreach ($this->files as $name => $file) {
            $zip->addFromString($name, $file['content']);
        }

        foreach ($this->signatures as $name => $xml) {
            $zip->addFromString($name, $xml);
        }

        $zip->close();
        rename($temporary, $path);
        $this->path = $path;

        return $path;
    }

    public function contents(): string
    {
        $path = tempnam(sys_get_temp_dir(), 'asice-');
        $this->save($path);
        $bytes = (string) file_get_contents($path);
        @unlink($path);

        return $bytes;
    }

    /**
     * What a verifier needs to know: does each signature still match its
     * files, is the signature value the signer's, and does the container
     * carry the time-stamp and revocation answer of a long-term signature.
     */
    public function validate(): ValidationResult
    {
        $signers = [];
        $errors = [];

        foreach ($this->signatures as $name => $xml) {
            try {
                $certificate = self::certificateOf($xml);
                $signature = XadesSignature::fromXml($xml, $certificate);
                $problems = [];

                foreach ($signature->references() as $file => $reference) {
                    $content = $this->files[$file]['content'] ?? null;

                    if ($content === null) {
                        $problems[] = "The container has no file {$file}.";

                        continue;
                    }

                    if (base64_encode(SignAlg::SHA256->digest($content)) !== $reference['digest']) {
                        $problems[] = "The file {$file} changed after it was signed.";
                    }
                }

                if (! $signature->verify()) {
                    $problems[] = 'The signature value does not match the signed data.';
                }

                $signedAt = $signature->signingTime();

                $signers[] = new SignerInfo(
                    name: $certificate->signerName(),
                    personalCode: $certificate->personalCode(),
                    signedAt: new DateTimeImmutable('@'.($signedAt ?? time())),
                    subject: $certificate->subject(),
                    valid: $problems === [],
                    errors: $problems,
                    timestamped: str_contains($xml, 'EncapsulatedTimeStamp'),
                    revocationChecked: str_contains($xml, 'EncapsulatedOCSPValue'),
                );
            } catch (Throwable $e) {
                $errors[] = "{$name}: {$e->getMessage()}";
            }
        }

        if ($this->signatures === []) {
            $errors[] = 'The container carries no signatures.';
        }

        return new ValidationResult($signers, $errors);
    }

    private static function certificateOf(string $xml): Certificate
    {
        if (preg_match('#<(?:ds:)?X509Certificate>([^<]+)</(?:ds:)?X509Certificate>#', $xml, $m) !== 1) {
            throw new RuntimeException('The signature carries no certificate.');
        }

        return Certificate::fromBase64($m[1]);
    }

    /** The issuer certificate, from the AIA of the signer's certificate. */
    private function fetchIssuer(Certificate $certificate): ?Certificate
    {
        $url = $certificate->issuerUrl();

        if ($url === null) {
            return null;
        }

        $bytes = @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => 10, 'ignore_errors' => true]]));

        if ($bytes === false || $bytes === '') {
            return null;
        }

        try {
            return str_contains($bytes, '-----BEGIN') ? Certificate::fromPem($bytes) : Certificate::fromDer($bytes);
        } catch (Throwable) {
            return null;
        }
    }
}
