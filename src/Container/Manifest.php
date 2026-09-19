<?php

declare(strict_types=1);

namespace Komma\Asice\Container;

use DOMDocument;

/**
 * META-INF/manifest.xml — the OpenDocument manifest ASiC-E borrows: the
 * container's own media type plus one entry per data file. Signatures are
 * not listed; only what they cover.
 */
final class Manifest
{
    public const NS = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0';

    /** @param array<string, array{mime: string, content: string}> $files */
    public static function build(array $files): string
    {
        $document = new DOMDocument('1.0', 'UTF-8');
        $document->formatOutput = true;

        $root = $document->createElementNS(self::NS, 'manifest:manifest');
        $root->setAttribute('manifest:version', '1.2');
        $document->appendChild($root);

        $container = $document->createElementNS(self::NS, 'manifest:file-entry');
        $container->setAttribute('manifest:full-path', '/');
        $container->setAttribute('manifest:media-type', Container::MIMETYPE);
        $root->appendChild($container);

        foreach ($files as $name => $file) {
            $entry = $document->createElementNS(self::NS, 'manifest:file-entry');
            $entry->setAttribute('manifest:full-path', $name);
            $entry->setAttribute('manifest:media-type', $file['mime']);
            $root->appendChild($entry);
        }

        return (string) $document->saveXML();
    }

    /** @return array<string, string> file name => media type */
    public static function parse(string $xml): array
    {
        if (trim($xml) === '') {
            return [];
        }

        $document = new DOMDocument;

        if (! @$document->loadXML($xml)) {
            return [];
        }

        $out = [];

        foreach ($document->getElementsByTagNameNS(self::NS, 'file-entry') as $entry) {
            $path = (string) $entry->getAttributeNS(self::NS, 'full-path');

            if ($path !== '' && $path !== '/') {
                $out[$path] = (string) $entry->getAttributeNS(self::NS, 'media-type');
            }
        }

        return $out;
    }
}
