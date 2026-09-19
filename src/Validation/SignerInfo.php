<?php

declare(strict_types=1);

namespace Komma\Asice\Validation;

use DateTimeImmutable;

final class SignerInfo
{
    public function __construct(
        private readonly string $name,
        private readonly ?string $personalCode,
        private readonly DateTimeImmutable $signedAt,
        private readonly string $subject,
        private readonly bool $valid,
        private readonly array $errors = [],
        private readonly bool $timestamped = false,
        private readonly bool $revocationChecked = false,
    ) {}

    public function name(): string
    {
        return $this->name;
    }

    public function personalCode(): ?string
    {
        return $this->personalCode;
    }

    public function signedAt(): DateTimeImmutable
    {
        return $this->signedAt;
    }

    public function subject(): string
    {
        return $this->subject;
    }

    public function isValid(): bool
    {
        return $this->valid;
    }

    public function errors(): array
    {
        return $this->errors;
    }

    /** True when the container carries a time-stamp and an OCSP answer: a long-term signature. */
    public function isLongTerm(): bool
    {
        return $this->timestamped && $this->revocationChecked;
    }
}
