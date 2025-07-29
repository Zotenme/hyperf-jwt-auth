<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Service;

use Hyperf\Cache\CacheManager as HyperfCacheManager;
use Hyperf\Contract\ConfigInterface;
use Zotenme\JwtAuth\Config\JwtConfig;
use Zotenme\JwtAuth\Contract\TokenStorageInterface;

/**
 * Unified token storage service that handles caching, blacklisting, and user token management.
 */
class TokenStorage implements TokenStorageInterface
{
    private const BLACKLIST_PREFIX = 'jwt_blacklist:';
    private const USER_TOKENS_PREFIX = 'jwt_user_tokens:';
    private const DEFAULT_CACHE_POOL = 'default';

    public function __construct(
        private readonly HyperfCacheManager $cacheManager,
        private readonly ConfigInterface $config,
        private readonly JwtConfig $jwtConfig
    ) {}

    /**
     * Stores a value in the cache.
     */
    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        $cache = $this->getCacheInstance();

        return $cache->set($key, $value, $ttl);
    }

    /**
     * Retrieves a value from the cache.
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $cache = $this->getCacheInstance();

        return $cache->get($key, $default);
    }

    /**
     * Deletes a value from the cache.
     */
    public function delete(string $key): bool
    {
        $cache = $this->getCacheInstance();

        return $cache->delete($key);
    }

    /**
     * Checks if a key exists in the cache.
     */
    public function exists(string $key): bool
    {
        $cache = $this->getCacheInstance();

        return $cache->has($key);
    }

    /**
     * Adds a token to the blacklist.
     */
    public function revokeToken(string $jti, ?int $ttl = null): void
    {
        if (!$this->isBlacklistEnabled()) {
            return;
        }

        $key = self::BLACKLIST_PREFIX . $jti;
        $this->set($key, true, $ttl);
    }

    /**
     * Checks if a token is revoked (in blacklist).
     */
    public function isTokenRevoked(string $jti): bool
    {
        if (!$this->isBlacklistEnabled()) {
            return false;
        }

        $key = self::BLACKLIST_PREFIX . $jti;

        return (bool) $this->get($key, false);
    }

    /**
     * Revokes all user tokens (for SSO mode).
     */
    public function revokeAllUserTokens(string $subjectId): void
    {
        $userTokens = $this->getUserActiveTokens($subjectId);

        foreach ($userTokens as $jti) {
            $this->revokeToken($jti);
        }

        $this->clearUserTokens($subjectId);
    }

    /**
     * Registers a new user token.
     */
    public function registerUserToken(string $subjectId, string $jti, bool $ssoMode = false): void
    {
        if ($ssoMode) {
            $this->clearUserTokens($subjectId);
        }

        $this->addUserToken($subjectId, $jti);
    }

    /**
     * Removes a token from the list of active user tokens.
     */
    public function unregisterUserToken(string $subjectId, string $jti): void
    {
        $this->removeUserToken($subjectId, $jti);
    }

    /**
     * Retrieves the list of active user tokens.
     *
     * @return array<string, mixed>
     */
    public function getUserActiveTokens(string $subjectId): array
    {
        return $this->getUserTokens($subjectId);
    }

    /**
     * Cleans up expired entries from the blacklist.
     * Note: This is handled automatically by the cache TTL mechanism.
     */
    public function cleanup(): void
    {
        // Cache entries with TTL are automatically cleaned up by the cache system
        // This method is kept for interface compatibility
    }

    /**
     * Checks if the blacklist is enabled.
     */
    public function isBlacklistEnabled(): bool
    {
        return $this->jwtConfig->isBlacklistEnabled();
    }

    /**
     * Checks if SSO mode is enabled.
     */
    public function isSsoModeEnabled(): bool
    {
        return $this->jwtConfig->isSsoModeEnabled();
    }

    /**
     * Adds a token to the list of active user tokens.
     */
    private function addUserToken(string $subjectId, string $jti, ?int $ttl = null): bool
    {
        $key = self::USER_TOKENS_PREFIX . $subjectId;
        $tokens = $this->get($key, []);

        if (!in_array($jti, $tokens, true)) {
            $tokens[] = $jti;

            return $this->set($key, $tokens, $ttl);
        }

        return true;
    }

    /**
     * Retrieves the list of active user tokens.
     *
     * @return array<string, mixed>
     */
    private function getUserTokens(string $subjectId): array
    {
        $key = self::USER_TOKENS_PREFIX . $subjectId;

        return (array) $this->get($key, []);
    }

    /**
     * Removes a token from the list of active user tokens.
     */
    private function removeUserToken(string $subjectId, string $jti): bool
    {
        $key = self::USER_TOKENS_PREFIX . $subjectId;
        $tokens = $this->get($key, []);

        $index = array_search($jti, $tokens, true);
        if ($index !== false) {
            unset($tokens[$index]);
            $tokens = array_values($tokens); // Reindex array

            return $this->set($key, $tokens);
        }

        return true;
    }

    /**
     * Clears all active user tokens.
     */
    private function clearUserTokens(string $subjectId): bool
    {
        $key = self::USER_TOKENS_PREFIX . $subjectId;

        return $this->delete($key);
    }

    /**
     * Gets the cache instance.
     *
     * @return mixed
     */
    private function getCacheInstance()
    {
        $pool = $this->config->get('jwt.cache.pool', self::DEFAULT_CACHE_POOL);

        return $this->cacheManager->getDriver($pool);
    }
}
