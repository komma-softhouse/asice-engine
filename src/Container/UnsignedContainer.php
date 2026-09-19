<?php

declare(strict_types=1);

namespace Komma\Asice\Container;

use RuntimeException;

/**
 * The files that are about to become a container. Kept apart from Container
 * on purpose: until something is signed, there is nothing to open, validate
 * or save twice.
 */
final class UnsignedContainer
{
    /** @var array<string, array{mime: string, content: string}> */
    private array $files = [];

    public static function make(): self
    {
        return new self;
    }

    public function addFile(string $name, string $content, string $mime = 'application/octet-stream'): self
    {
        $name = ltrim(str_replace('\\', '/', $name), '/');

        if ($name === '' || str_starts_with($name, 'META-INF/') || $name === 'mimetype') {
            throw new RuntimeException("A data file cannot be named {$name}.");
        }

        $this->files[$name] = ['mime' => $mime, 'content' => $content];

        return $this;
    }

    public function addPath(string $path, ?string $name = null, ?string $mime = null): self
    {
        if (! is_file($path)) {
            throw new RuntimeException("There is no file at {$path}.");
        }

        return $this->addFile($name ?? basename($path), (string) file_get_contents($path), $mime ?? (mime_content_type($path) ?: 'application/octet-stream'));
    }

    /** @return array<string, array{mime: string, content: string}> */
    public function files(): array
    {
        return $this->files;
    }

    public function build(?string $path = null): Container
    {
        if ($this->files === []) {
            throw new RuntimeException('A container needs at least one file.');
        }

        $container = Container::fromFiles($this->files, $path);

        if ($path !== null) {
            $container->save($path);
        }

        return $container;
    }
}
