<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Contract;

/**
 * Interface for unified token storage operations.
 */
interface TokenStorageInterface
{
    /**
     * Stores a value in the cache.
     */
    public function set(string $key, mixed $value, ?int $ttl = null): bool;

    /**
     * Retrieves a value from the cache.
     */
    public function get(string $key, mixed $default = null): mixed;

    /**
     * Deletes a value from the cache.
     */
    public function delete(string $key): bool;

    /**
     * Checks if a key exists in the cache.
     */
    public function exists(string $key): bool;

    /**
     * Adds a token to the blacklist.
     */
    public function revokeToken(string $jti, ?int $ttl = null): void;

    /**
     * Checks if a token is revoked (in blacklist).
     */
    public function isTokenRevoked(string $jti): bool;

    /**
     * Revokes all user tokens (for SSO mode).
     */
    public function revokeAllUserTokens(string $subjectId): void;

    /**
     * Registers a new user token.
     */
    public function registerUserToken(string $subjectId, string $jti, bool $ssoMode = false): void;

    /**
     * Removes a token from the list of active user tokens.
     */
    public function unregisterUserToken(string $subjectId, string $jti): void;

    /**
     * Retrieves the list of active user tokens.
     *
     * @return array<string, mixed>
     */
    public function getUserActiveTokens(string $subjectId): array;

    /**
     * Cleans up expired entries from the blacklist.
     */
    public function cleanup(): void;

    /**
     * Checks if the blacklist is enabled.
     */
    public function isBlacklistEnabled(): bool;

    /**
     * Checks if SSO mode is enabled.
     */
    public function isSsoModeEnabled(): bool;
}
