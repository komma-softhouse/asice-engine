<?php

declare(strict_types=1);

namespace Komma\Asice\Crypto;

use DOMDocument;
use DOMNode;

/**
 * Exclusive XML canonicalisation, the only transform these containers use.
 * PHP's DOM does it natively; the wrapper keeps the call identical
 * everywhere, because a byte of difference here breaks every signature.
 */
final class C14n
{
    public const METHOD = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    public static function node(DOMNode $node): string
    {
        return (string) $node->C14N(true, false);
    }

    public static function document(DOMDocument $document): string
    {
        return (string) $document->C14N(true, false);
    }
}
