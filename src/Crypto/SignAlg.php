<?php

declare(strict_types=1);

namespace Komma\Asice\Crypto;

/**
 * The digest and signature algorithms Estonian eID uses. ID-kaart cards from
 * 2018 sign with ECDSA; Smart-ID and Mobile-ID with RSA. The container says
 * which one, so both ends must agree before the hash is produced.
 */
enum SignAlg: string
{
    case SHA256 = 'SHA-256';
    case SHA384 = 'SHA-384';
    case SHA512 = 'SHA-512';

    public function hashAlgorithm(): string
    {
        return match ($this) {
            self::SHA256 => 'sha256',
            self::SHA384 => 'sha384',
            self::SHA512 => 'sha512',
        };
    }

    public function digest(string $data): string
    {
        return hash($this->hashAlgorithm(), $data, true);
    }

    public function digestMethodUri(): string
    {
        return match ($this) {
            self::SHA256 => 'http://www.w3.org/2001/04/xmlenc#sha256',
            self::SHA384 => 'http://www.w3.org/2001/04/xmldsig-more#sha384',
            self::SHA512 => 'http://www.w3.org/2001/04/xmlenc#sha512',
        };
    }

    /** The XML signature method for the key type of the signer's certificate. */
    public function signatureMethodUri(string $keyType): string
    {
        return $keyType === 'EC'
            ? match ($this) {
                self::SHA256 => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
                self::SHA384 => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
                self::SHA512 => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
            }
            : match ($this) {
                self::SHA256 => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
                self::SHA384 => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
                self::SHA512 => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
            };
    }

    public function digestOid(): string
    {
        return match ($this) {
            self::SHA256 => '2.16.840.1.101.3.4.2.1',
            self::SHA384 => '2.16.840.1.101.3.4.2.2',
            self::SHA512 => '2.16.840.1.101.3.4.2.3',
        };
    }
}
