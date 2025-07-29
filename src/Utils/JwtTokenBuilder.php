<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Utils;

use Lcobucci\JWT\Configuration;
use Ramsey\Uuid\Uuid;
use Zotenme\JwtAuth\Config\JwtConfig;
use Zotenme\JwtAuth\Contract\TokenStorageInterface;
use Zotenme\JwtAuth\DTO\TokenPair;
use Zotenme\JwtAuth\Exception\JwtException;
use Zotenme\JwtAuth\Factory\JwtConfigurationFactory;

/**
 * Builder for JWT tokens.
 */
class JwtTokenBuilder
{
    private Configuration $jwtConfiguration;

    public function __construct(
        private readonly JwtConfig $config,
        private readonly JwtConfigurationFactory $configurationFactory,
        private readonly TokenStorageInterface $tokenStorage
    ) {
        $this->jwtConfiguration = $this->configurationFactory->create();
    }

    /**
     * Creates a token pair (access + refresh).
     *
     * @param array<string, mixed> $payload
     */
    public function createTokenPair(string $subjectId, array $payload = []): TokenPair
    {
        if (empty($subjectId)) {
            throw new JwtException('Subject ID cannot be empty');
        }

        $now = new \DateTimeImmutable();

        // Build access token
        $accessTokenJti = Uuid::uuid4()->toString();
        $accessToken = $this->buildToken(
            $accessTokenJti,
            $subjectId,
            $now,
            $this->config->getAccessTokenTtl(),
            'access',
            $payload
        );

        // Build refresh token
        $refreshTokenJti = Uuid::uuid4()->toString();
        $refreshToken = $this->buildToken(
            $refreshTokenJti,
            $subjectId,
            $now,
            $this->config->getRefreshTokenTtl(),
            'refresh',
            array_merge($payload, ['access_jti' => $accessTokenJti])
        );

        // Register tokens
        $ssoMode = $this->tokenStorage->isSsoModeEnabled();
        $this->tokenStorage->registerUserToken($subjectId, $accessTokenJti, $ssoMode);
        $this->tokenStorage->registerUserToken($subjectId, $refreshTokenJti, $ssoMode);

        return new TokenPair(
            $accessToken,
            $refreshToken,
            $this->config->getAccessTokenTtl(),
            $this->config->getRefreshTokenTtl()
        );
    }

    /**
     * Creates a single access token.
     *
     * @param array<string, mixed> $payload
     */
    public function createAccessToken(string $subjectId, array $payload = []): string
    {
        $jti = Uuid::uuid4()->toString();
        $token = $this->buildToken(
            $jti,
            $subjectId,
            new \DateTimeImmutable(),
            $this->config->getAccessTokenTtl(),
            'access',
            $payload
        );

        // Register token
        $ssoMode = $this->tokenStorage->isSsoModeEnabled();
        $this->tokenStorage->registerUserToken($subjectId, $jti, $ssoMode);

        return $token;
    }

    /**
     * Builds a single token.
     *
     * @param array<string, mixed> $customClaims
     */
    public function buildToken(
        string $jti,
        string $subjectId,
        \DateTimeImmutable $now,
        int $ttl,
        string $type,
        array $customClaims = []
    ): string {
        $issuer = $this->config->getIssuer();
        $audience = $this->config->getConfig()['audience'] ?? null;

        $builder = $this->jwtConfiguration->builder();

        if (!empty($jti)) {
            $builder = $builder->identifiedBy($jti);
        }

        $builder = $builder
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify("+{$ttl} seconds"))
            ->withClaim('type', $type)
        ;

        if (!empty($issuer)) {
            $builder = $builder->issuedBy($issuer);
        }

        if (!empty($audience)) {
            $builder = $builder->permittedFor($audience);
        }

        if (!empty($subjectId)) {
            $builder = $builder->relatedTo($subjectId);
        }

        foreach ($customClaims as $key => $value) {
            if (is_string($key) && $key !== '') {
                $builder = $builder->withClaim($key, $value);
            }
        }

        return $builder->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey())->toString();
    }
}
