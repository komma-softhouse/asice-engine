<?php

declare(strict_types=1);

namespace Komma\Asice\Validation;

final class ValidationResult
{
    /** @param list<SignerInfo> $signatures */
    public function __construct(
        private readonly array $signatures,
        private readonly array $errors = [],
    ) {}

    public function isValid(): bool
    {
        if ($this->errors !== [] || $this->signatures === []) {
            return false;
        }

        foreach ($this->signatures as $signature) {
            if (! $signature->isValid()) {
                return false;
            }
        }

        return true;
    }

    /** @return list<SignerInfo> */
    public function signatures(): array
    {
        return $this->signatures;
    }

    public function errors(): array
    {
        return $this->errors;
    }
}
