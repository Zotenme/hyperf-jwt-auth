<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf JWT Auth.
 *
 * @link     https://github.com/Zotenme/hyperf-jwt-auth
 * @document https://github.com/Zotenme/hyperf-jwt-auth/blob/main/README.md
 * @contact  zotenme@gmail.com
 * @license  https://github.com/Zotenme/hyperf-jwt-auth/blob/main/LICENSE
 */

namespace Zotenme\JwtAuth\DTO;

use Lcobucci\JWT\Token\RegisteredClaims;

/**
 * DTO for JWT token payload.
 */
readonly class JwtPayload
{
    /**
     * @param string               $subject      Token subject (usually user ID)
     * @param int                  $issuedAt     Token creation time (timestamp)
     * @param int                  $expiresAt    Token expiration time (timestamp)
     * @param string               $jwtId        Unique token identifier
     * @param array<string, mixed> $customClaims Additional claims
     */
    public function __construct(
        public string $subject,
        public int $issuedAt,
        public int $expiresAt,
        public string $jwtId,
        public array $customClaims = []
    ) {}

    /**
     * Checks if the token has expired.
     */
    public function isExpired(): bool
    {
        return time() >= $this->expiresAt;
    }

    /**
     * Retrieves the value of a custom claim.
     */
    public function getClaim(string $key, mixed $default = null): mixed
    {
        // Check standard claims first
        return match ($key) {
            'sub', RegisteredClaims::SUBJECT => $this->subject,
            'iat', RegisteredClaims::ISSUED_AT => $this->issuedAt,
            'exp', RegisteredClaims::EXPIRATION_TIME => $this->expiresAt,
            'jti', RegisteredClaims::ID => $this->jwtId,
            default => $this->customClaims[$key] ?? $default,
        };
    }

    /**
     * Converts to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_merge([
            RegisteredClaims::SUBJECT => $this->subject,
            RegisteredClaims::ISSUED_AT => $this->issuedAt,
            RegisteredClaims::EXPIRATION_TIME => $this->expiresAt,
            RegisteredClaims::ID => $this->jwtId,
        ], $this->customClaims);
    }

    /**
     * Creates an instance from an array of claims.
     *
     * @param array<string, mixed> $claims
     */
    public static function fromArray(array $claims): self
    {
        $standardClaims = [RegisteredClaims::SUBJECT, RegisteredClaims::ISSUED_AT, RegisteredClaims::EXPIRATION_TIME, RegisteredClaims::ID];
        $customClaims = array_diff_key($claims, array_flip($standardClaims));

        return new self(
            subject: (string) ($claims[RegisteredClaims::SUBJECT] ?? ''),
            issuedAt: (int) ($claims[RegisteredClaims::ISSUED_AT] ?? 0),
            expiresAt: (int) ($claims[RegisteredClaims::EXPIRATION_TIME] ?? 0),
            jwtId: (string) ($claims[RegisteredClaims::ID] ?? ''),
            customClaims: $customClaims
        );
    }
}
