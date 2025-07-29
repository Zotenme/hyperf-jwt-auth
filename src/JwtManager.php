<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth;

use Lcobucci\JWT\Token\RegisteredClaims;
use Zotenme\JwtAuth\Config\JwtConfig;
use Zotenme\JwtAuth\Contract\JwtManagerInterface;
use Zotenme\JwtAuth\Contract\TokenStorageInterface;
use Zotenme\JwtAuth\DTO\JwtPayload;
use Zotenme\JwtAuth\DTO\TokenPair;
use Zotenme\JwtAuth\Exception\JwtException;
use Zotenme\JwtAuth\Exception\TokenInvalidException;
use Zotenme\JwtAuth\Utils\JwtTokenBuilder;
use Zotenme\JwtAuth\Utils\JwtTokenValidator;

/**
 * Main manager for working with JWT tokens.
 */
class JwtManager implements JwtManagerInterface
{
    public function __construct(
        private readonly JwtConfig $config,
        private readonly TokenStorageInterface $tokenStorage,
        private readonly JwtTokenBuilder $tokenBuilder,
        private readonly JwtTokenValidator $tokenValidator
    ) {}

    /**
     * Generates a token pair (access + refresh).
     */
    public function generateTokenPair(string $subjectId, array $payload = []): TokenPair
    {
        if (empty($subjectId)) {
            throw new JwtException('Subject ID cannot be empty');
        }

        // In SSO mode, revoke all old subject tokens
        if ($this->tokenStorage->isSsoModeEnabled()) {
            $this->tokenStorage->revokeAllSubjectTokens($subjectId);
        }

        return $this->tokenBuilder->createTokenPair($subjectId, $payload);
    }

    /**
     * Refreshes the access token using the refresh token.
     */
    public function refreshAccessToken(string $refreshToken): TokenPair
    {
        $payload = $this->validateRefreshToken($refreshToken);
        $subjectId = $payload->subject;
        $customClaims = $payload->customClaims;

        // Remove system claims from custom claims
        unset($customClaims['access_jti']);

        // If refresh token rotation is enabled
        if ($this->config->isRefreshTokenRotationEnabled()) {
            $this->revokeToken($refreshToken);

            return $this->generateTokenPair($subjectId, $customClaims);
        }

        // Generate only new access token
        $accessToken = $this->tokenBuilder->createAccessToken($subjectId, $customClaims);

        return new TokenPair(
            $accessToken,
            $refreshToken,
            $this->config->getAccessTokenTtl(),
            $this->config->getRefreshTokenTtl()
        );
    }

    /**
     * Validates the access token.
     */
    public function validateAccessToken(string $accessToken): JwtPayload
    {
        return $this->tokenValidator->validateAccessToken($accessToken);
    }

    /**
     * Validates the refresh token.
     */
    public function validateRefreshToken(string $refreshToken): JwtPayload
    {
        return $this->tokenValidator->validateRefreshToken($refreshToken);
    }

    /**
     * Revokes a token (adds to blacklist).
     */
    public function revokeToken(string $token): void
    {
        if (empty($token)) {
            throw new TokenInvalidException('Token cannot be empty');
        }

        try {
            $parsedToken = $this->tokenValidator->parseTokenWithoutValidation($token);

            $jti = $parsedToken->claims()->get(RegisteredClaims::ID);

            if (!$jti) {
                throw new TokenInvalidException('Token does not have JTI claim');
            }

            $exp = $parsedToken->claims()->get(RegisteredClaims::EXPIRATION_TIME);
            $ttl = $exp instanceof \DateTimeImmutable
                ? max(0, $exp->getTimestamp() - time())
                : null;

            $this->tokenStorage->revokeToken($jti, $ttl);

            $subjectId = $parsedToken->claims()->get(RegisteredClaims::SUBJECT);

            if ($subjectId) {
                $this->tokenStorage->unregisterSubjectToken($subjectId, $jti);
            }
        } catch (\Exception $e) {
            throw new JwtException('Failed to revoke token: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Revokes all tokens for a specific subject.
     */
    public function revokeAllSubjectTokens(string $subjectId): void
    {
        if (empty($subjectId)) {
            throw new JwtException('Subject ID cannot be empty');
        }

        try {
            $this->tokenStorage->revokeAllSubjectTokens($subjectId);
        } catch (\Exception $e) {
            throw new JwtException('Failed to revoke all subject tokens: ' . $e->getMessage(), 0, $e);
        }
    }
}
