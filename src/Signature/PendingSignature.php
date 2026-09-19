<?php

declare(strict_types=1);

namespace Komma\Asice\Signature;

use Komma\Asice\Crypto\Certificate;
use Komma\Asice\Crypto\SignAlg;

/**
 * A signature waiting for its value. It carries everything the finish step
 * needs and nothing that cannot survive a round trip through a queue, a
 * session or a database row: the XML as text, the certificate as base64.
 */
final class PendingSignature
{
    public function __construct(
        public readonly XadesSignature $signature,
        public readonly Certificate $certificate,
        public readonly SignAlg $alg,
        public readonly string $hash,
    ) {}

    public function getHash(): string
    {
        return $this->hash;
    }

    public function getHashBase64(): string
    {
        return base64_encode($this->hash);
    }

    public function serialize(): string
    {
        return base64_encode(json_encode([
            'xml' => $this->signature->xml(),
            'certificate' => $this->certificate->base64(),
            'alg' => $this->alg->value,
            'hash' => base64_encode($this->hash),
        ], JSON_THROW_ON_ERROR));
    }

    public static function unserialize(string $state): self
    {
        $data = json_decode((string) base64_decode($state, true), true, 512, JSON_THROW_ON_ERROR);
        $certificate = Certificate::fromBase64((string) $data['certificate']);
        $alg = SignAlg::from((string) $data['alg']);

        return new self(
            XadesSignature::fromXml((string) $data['xml'], $certificate, $alg),
            $certificate,
            $alg,
            (string) base64_decode((string) $data['hash'], true),
        );
    }
}
