<?php

declare(strict_types=1);

namespace Komma\Asice\Tsa;

use Komma\Asice\Asn1\Der;
use Komma\Asice\Crypto\SignAlg;
use RuntimeException;

/**
 * RFC 3161 time-stamp over the signature value. It is what proves the
 * signature existed before the certificate expired, and what Estonian
 * practice expects in an ASiC-E container (SK's tsa.sk.ee, or any TSA the
 * host prefers).
 */
final class TimestampClient
{
    public function __construct(
        private readonly string $url = 'http://tsa.sk.ee',
        private readonly int $timeout = 10,
    ) {}

    /** @return array{der: string, generated_at: ?int} */
    public function stamp(string $data, SignAlg $alg = SignAlg::SHA256): array
    {
        $response = $this->post($this->request($alg->digest($data), $alg));
        $token = $this->token($response);

        return ['der' => $token, 'generated_at' => $this->generatedAt($token)];
    }

    /** TimeStampReq ::= SEQUENCE { version, messageImprint, nonce, certReq } */
    public function request(string $digest, SignAlg $alg = SignAlg::SHA256): string
    {
        return Der::sequence(
            Der::integer(1),
            Der::sequence(
                Der::sequence(Der::oid($alg->digestOid()), Der::null()),
                Der::octetString($digest),
            ),
            Der::integerFromBytes(random_bytes(8)),
            Der::boolean(true),
        );
    }

    /** Pull the ContentInfo (the token itself) out of the TimeStampResp. */
    public function token(string $response): string
    {
        $children = Der::children(Der::read($response)['value']);

        if (($children[0]['tag'] ?? 0) === Der::SEQUENCE) {
            $status = Der::children($children[0]['value'])[0] ?? null;

            if ($status !== null && ltrim($status['value'], "\x00") !== '' && ord($status['value']) > 1) {
                throw new RuntimeException('The time-stamp authority refused the request.');
            }
        }

        $token = $children[1] ?? throw new RuntimeException('The time-stamp answer carries no token.');

        return $token['raw'];
    }

    public function generatedAt(string $token): ?int
    {
        // TSTInfo lives inside the CMS content; the first GeneralizedTime in
        // the token is its genTime.
        if (preg_match('/(\d{14})(?:\.\d+)?Z/', $token, $m) === 1) {
            return strtotime($m[1].' UTC') ?: null;
        }

        return null;
    }

    private function post(string $body): string
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/timestamp-query\r\nAccept: application/timestamp-reply\r\n",
                'content' => $body,
                'timeout' => $this->timeout,
                'ignore_errors' => true,
            ],
        ]);

        $response = @file_get_contents($this->url, false, $context);

        if ($response === false || $response === '') {
            throw new RuntimeException("The time-stamp authority at {$this->url} did not answer.");
        }

        return $response;
    }
}
