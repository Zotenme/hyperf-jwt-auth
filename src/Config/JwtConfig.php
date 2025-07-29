<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Config;

use Hyperf\Contract\ConfigInterface;
use Zotenme\JwtAuth\Exception\JwtException;

/**
 * Class for working with JWT configuration.
 */
class JwtConfig
{
    private const CONFIG_KEY = 'jwt';

    public function __construct(
        private readonly ConfigInterface $config
    ) {}

    /**
     * Retrieves the signing algorithm.
     *
     * @throws JwtException
     */
    public function getAlgorithm(): JwtAlgorithm
    {
        $algorithm = $this->config->get(self::CONFIG_KEY . '.algorithm', 'HS256');

        if (!in_array($algorithm, JwtAlgorithm::getSupported(), true)) {
            throw new JwtException("Unsupported algorithm: {$algorithm}");
        }

        return JwtAlgorithm::from($algorithm);
    }

    /**
     * Retrieves the secret key for HMAC algorithms.
     *
     * @throws JwtException
     */
    public function getSecretKey(): string
    {
        $key = $this->config->get(self::CONFIG_KEY . '.keys.secret_key');

        if (empty($key)) {
            throw new JwtException('Secret key is not configured');
        }

        return $key;
    }

    /**
     * Retrieves the private key for RSA algorithms.
     *
     * @throws JwtException
     */
    public function getPrivateKey(): string
    {
        $key = $this->config->get(self::CONFIG_KEY . '.keys.private_key');

        if (empty($key)) {
            throw new JwtException('Private key is not configured');
        }

        // If it's a file path, read the content
        if (is_file($key)) {
            $content = file_get_contents($key);

            if ($content === false) {
                throw new JwtException("Cannot read private key file: {$key}");
            }

            return $content;
        }

        return $key;
    }

    /**
     * Retrieves the public key for RSA algorithms.
     *
     * @throws JwtException
     */
    public function getPublicKey(): string
    {
        $key = $this->config->get(self::CONFIG_KEY . '.keys.public_key');

        if (empty($key)) {
            throw new JwtException('Public key is not configured');
        }

        // If it's a file path, read the content
        if (is_file($key)) {
            $content = file_get_contents($key);
            if ($content === false) {
                throw new JwtException("Cannot read public key file: {$key}");
            }

            return $content;
        }

        return $key;
    }

    /**
     * Retrieves the passphrase for the private key.
     */
    public function getPassphrase(): string
    {
        return $this->config->get(self::CONFIG_KEY . '.keys.passphrase', '');
    }

    /**
     * Retrieves the TTL for the access token in seconds.
     */
    public function getAccessTokenTtl(): int
    {
        return $this->config->get(self::CONFIG_KEY . '.access_token.ttl', 900);
    }

    /**
     * Retrieves the TTL for the refresh token in seconds.
     */
    public function getRefreshTokenTtl(): int
    {
        return $this->config->get(self::CONFIG_KEY . '.refresh_token.ttl', 604800);
    }

    /**
     * Checks if refresh token rotation is enabled.
     */
    public function isRefreshTokenRotationEnabled(): bool
    {
        return $this->config->get(self::CONFIG_KEY . '.refresh_token.rotation_enabled', false);
    }

    /**
     * Retrieves the prefix for cache keys.
     */
    public function getCachePrefix(): string
    {
        return $this->config->get(self::CONFIG_KEY . '.cache.prefix', 'jwt_auth:');
    }

    /**
     * Retrieves the TTL for the cache.
     */
    public function getCacheTtl(): ?int
    {
        return $this->config->get(self::CONFIG_KEY . '.cache.ttl');
    }

    /**
     * Checks if the blacklist is enabled.
     */
    public function isBlacklistEnabled(): bool
    {
        return $this->config->get(self::CONFIG_KEY . '.blacklist.enabled', true);
    }

    /**
     * Retrieves the grace period for the blacklist in seconds.
     */
    public function getBlacklistGracePeriod(): int
    {
        return $this->config->get(self::CONFIG_KEY . '.blacklist.grace_period', 0);
    }

    /**
     * Checks if SSO mode is enabled.
     */
    public function isSsoModeEnabled(): bool
    {
        return $this->config->get(self::CONFIG_KEY . '.sso_mode', false);
    }

    /**
     * Retrieves the token issuer.
     */
    public function getIssuer(): string
    {
        return $this->config->get(self::CONFIG_KEY . '.issuer') ?? 'jwt-auth';
    }

    /**
     * Validates key configuration for the current algorithm.
     *
     * @throws JwtException
     */
    public function validateKeys(): void
    {
        $algorithm = $this->getAlgorithm();

        if ($algorithm->isSymmetric()) {
            $this->getSecretKey(); // Checks for the presence of the secret key
        } else {
            $this->getPrivateKey(); // Checks for the presence of the private key
            $this->getPublicKey();  // Checks for the presence of the public key
        }
    }

    /**
     * Retrieves the full JWT configuration.
     *
     * @return array<string, mixed>
     */
    public function getConfig(): array
    {
        return $this->config->get(self::CONFIG_KEY, []);
    }
}
