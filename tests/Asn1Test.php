<?php

declare(strict_types=1);

use Komma\Asice\Asn1\Der;
use Komma\Asice\Crypto\SignAlg;
use Komma\Asice\Ocsp\OcspClient;
use Komma\Asice\Tsa\TimestampClient;

it('encodes object identifiers the way DER does', function () {
    expect(bin2hex(Der::oid('1.3.14.3.2.26')))->toBe('06052b0e03021a')
        ->and(bin2hex(Der::oid('2.16.840.1.101.3.4.2.1')))->toBe('0609608648016503040201')
        ->and(Der::oidValue(Der::oid('1.2.840.113549.1.1.11')))->toBe('1.2.840.113549.1.1.11');
});

it('encodes lengths over 127 bytes with the long form', function () {
    $value = str_repeat('A', 300);
    $der = Der::octetString($value);

    expect(bin2hex(substr($der, 0, 4)))->toBe('0482012c')
        ->and(Der::read($der)['value'])->toBe($value);
});

it('pads integers whose first bit is set', function () {
    expect(bin2hex(Der::integerFromBytes("\xFF\x01")))->toBe('020300ff01')
        ->and(bin2hex(Der::integer(1)))->toBe('020101');
});

it('builds a time-stamp request with the message imprint', function () {
    $request = (new TimestampClient)->request(SignAlg::SHA256->digest('hello'));
    $imprint = Der::find($request, [1, 1]);

    expect($imprint['value'])->toBe(SignAlg::SHA256->digest('hello'))
        ->and(Der::oidValue(Der::find($request, [1, 0, 0])['raw']))->toBe('2.16.840.1.101.3.4.2.1');
});

it('rejects an OCSP answer that is not successful', function () {
    expect(fn () => (new OcspClient)->parse(Der::sequence(chr(0x0A).chr(1).chr(6))))->toThrow(RuntimeException::class);
});
