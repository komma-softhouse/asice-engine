<?php

declare(strict_types=1);

namespace Komma\Asice\Asn1;

use RuntimeException;

/**
 * The slice of ASN.1 DER this engine needs: enough to build an OCSP request
 * and a timestamp request, and to walk the answers. Not a general library —
 * every method here exists because a signature step required it.
 */
final class Der
{
    public const SEQUENCE = 0x30;

    public const SET = 0x31;

    public const INTEGER = 0x02;

    public const BIT_STRING = 0x03;

    public const OCTET_STRING = 0x04;

    public const NULL = 0x05;

    public const OID = 0x06;

    public const BOOLEAN = 0x01;

    public const GENERALIZED_TIME = 0x18;

    /* ---------------------------------------------------------------- write */

    public static function tlv(int $tag, string $value): string
    {
        return chr($tag).self::length(strlen($value)).$value;
    }

    public static function sequence(string ...$parts): string
    {
        return self::tlv(self::SEQUENCE, implode('', $parts));
    }

    public static function set(string ...$parts): string
    {
        return self::tlv(self::SET, implode('', $parts));
    }

    public static function octetString(string $value): string
    {
        return self::tlv(self::OCTET_STRING, $value);
    }

    public static function bitString(string $value, int $unusedBits = 0): string
    {
        return self::tlv(self::BIT_STRING, chr($unusedBits).$value);
    }

    public static function null(): string
    {
        return "\x05\x00";
    }

    public static function boolean(bool $value): string
    {
        return self::tlv(self::BOOLEAN, $value ? "\xFF" : "\x00");
    }

    /** An unsigned integer given as raw big-endian bytes (a serial number, typically). */
    public static function integerFromBytes(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '') {
            $bytes = "\x00";
        }

        if (ord($bytes[0]) > 0x7F) {
            $bytes = "\x00".$bytes;
        }

        return self::tlv(self::INTEGER, $bytes);
    }

    public static function integer(int $value): string
    {
        $bytes = '';

        do {
            $bytes = chr($value & 0xFF).$bytes;
            $value >>= 8;
        } while ($value > 0);

        if (ord($bytes[0]) > 0x7F) {
            $bytes = "\x00".$bytes;
        }

        return self::tlv(self::INTEGER, $bytes);
    }

    /** A dotted OID string, e.g. "1.3.14.3.2.26". */
    public static function oid(string $dotted): string
    {
        $parts = array_map('intval', explode('.', $dotted));
        $body = chr($parts[0] * 40 + $parts[1]);

        foreach (array_slice($parts, 2) as $part) {
            $stack = [$part & 0x7F];
            $part >>= 7;

            while ($part > 0) {
                array_unshift($stack, ($part & 0x7F) | 0x80);
                $part >>= 7;
            }

            $body .= implode('', array_map('chr', $stack));
        }

        return self::tlv(self::OID, $body);
    }

    /** A context-specific constructed tag: [n] { … }. */
    public static function context(int $number, string $value, bool $constructed = true): string
    {
        return self::tlv(0x80 | ($constructed ? 0x20 : 0x00) | $number, $value);
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xFF).$bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)).$bytes;
    }

    /* ----------------------------------------------------------------- read */

    /**
     * Read one TLV at $offset.
     *
     * @return array{tag: int, length: int, header: int, value: string, end: int}
     */
    public static function read(string $der, int $offset = 0): array
    {
        if ($offset + 2 > strlen($der)) {
            throw new RuntimeException('Truncated DER.');
        }

        $tag = ord($der[$offset]);
        $first = ord($der[$offset + 1]);

        if ($first < 0x80) {
            $length = $first;
            $header = 2;
        } else {
            $count = $first & 0x7F;
            $length = 0;

            for ($i = 0; $i < $count; $i++) {
                $length = ($length << 8) | ord($der[$offset + 2 + $i]);
            }

            $header = 2 + $count;
        }

        return [
            'tag' => $tag,
            'length' => $length,
            'header' => $header,
            'value' => substr($der, $offset + $header, $length),
            'end' => $offset + $header + $length,
        ];
    }

    /** Every direct child of a constructed TLV body. */
    public static function children(string $value): array
    {
        $out = [];
        $offset = 0;

        while ($offset < strlen($value)) {
            $node = self::read($value, $offset);
            $node['raw'] = substr($value, $offset, $node['end'] - $offset);
            $out[] = $node;
            $offset = $node['end'];
        }

        return $out;
    }

    /**
     * Walk a path of child indexes: find($der, [0, 1, 0]) returns the TLV
     * three levels down. Null when the path does not exist.
     */
    public static function find(string $der, array $path): ?array
    {
        $node = self::read($der);

        foreach ($path as $index) {
            $children = self::children($node['value']);

            if (! isset($children[$index])) {
                return null;
            }

            $node = $children[$index];
        }

        return $node;
    }

    public static function oidValue(string $der): string
    {
        $node = self::read($der);
        $body = $node['value'];
        $first = ord($body[0]);
        $parts = [intdiv($first, 40), $first % 40];
        $value = 0;

        for ($i = 1; $i < strlen($body); $i++) {
            $byte = ord($body[$i]);
            $value = ($value << 7) | ($byte & 0x7F);

            if (($byte & 0x80) === 0) {
                $parts[] = $value;
                $value = 0;
            }
        }

        return implode('.', $parts);
    }
}
