<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Config;

/**
 * Enum for supported JWT algorithms.
 */
enum JwtAlgorithm: string
{
    case HS256 = 'HS256';
    case HS384 = 'HS384';
    case HS512 = 'HS512';
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';

    /**
     * Checks if the algorithm is symmetric (HMAC).
     */
    public function isSymmetric(): bool
    {
        return match ($this) {
            self::HS256, self::HS384, self::HS512 => true,
            self::RS256, self::RS384, self::RS512,
            self::ES256, self::ES384, self::ES512 => false,
        };
    }

    /**
     * Checks if the algorithm is asymmetric (RSA/ECDSA).
     */
    public function isAsymmetric(): bool
    {
        return !$this->isSymmetric();
    }

    /**
     * Checks if the algorithm is ECDSA.
     */
    public function isEcdsa(): bool
    {
        return match ($this) {
            self::ES256, self::ES384, self::ES512 => true,
            default => false,
        };
    }

    /**
     * Retrieves all supported algorithms.
     *
     * @return array<string>
     */
    public static function getSupported(): array
    {
        return array_map(fn (self $case) => $case->value, self::cases());
    }

    /**
     * Retrieves HMAC algorithms.
     *
     * @return array<string>
     */
    public static function getSymmetric(): array
    {
        return [self::HS256->value, self::HS384->value, self::HS512->value];
    }

    /**
     * Retrieves RSA algorithms.
     *
     * @return array<string>
     */
    public static function getAsymmetric(): array
    {
        return [self::RS256->value, self::RS384->value, self::RS512->value];
    }

    /**
     * Retrieves ECDSA algorithms.
     *
     * @return array<string>
     */
    public static function getEcdsa(): array
    {
        return [self::ES256->value, self::ES384->value, self::ES512->value];
    }

    /**
     * Creates an instance from a string with validation.
     *
     * @throws \ValueError
     */
    public static function fromString(string $algorithm): self
    {
        return self::from($algorithm);
    }
}
