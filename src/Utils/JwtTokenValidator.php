<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Utils;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Psr\Clock\ClockInterface;
use Zotenme\JwtAuth\Config\JwtConfig;
use Zotenme\JwtAuth\Contract\TokenStorageInterface;
use Zotenme\JwtAuth\DTO\JwtPayload;
use Zotenme\JwtAuth\Exception\TokenBlacklistedException;
use Zotenme\JwtAuth\Exception\TokenExpiredException;
use Zotenme\JwtAuth\Exception\TokenInvalidException;
use Zotenme\JwtAuth\Factory\JwtConfigurationFactory;

/**
 * Validator for JWT tokens.
 */
class JwtTokenValidator
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
     * Validates the access token.
     */
    public function validateAccessToken(string $accessToken): JwtPayload
    {
        return $this->validateTokenByType($accessToken, 'access');
    }

    /**
     * Validates the refresh token.
     */
    public function validateRefreshToken(string $refreshToken): JwtPayload
    {
        return $this->validateTokenByType($refreshToken, 'refresh');
    }

    /**
     * Validates token by type.
     */
    public function validateTokenByType(string $tokenString, string $expectedType): JwtPayload
    {
        if (empty($tokenString)) {
            throw new TokenInvalidException('Token cannot be empty');
        }

        try {
            $token = $this->jwtConfiguration->parser()->parse($tokenString);

            if (!$token instanceof UnencryptedToken) {
                throw new TokenInvalidException('Invalid token format');
            }

            if ($expectedType !== $token->claims()->get('type')) {
                throw new TokenInvalidException('Invalid token type');
            }

            $jti = $token->claims()->get(RegisteredClaims::ID);
            if ($jti && $this->tokenStorage->isTokenRevoked($jti)) {
                throw new TokenBlacklistedException('Token has been revoked');
            }

            $this->validateToken($token);

            return $this->createPayloadFromToken($token);
        } catch (\Throwable $e) {
            if ($e instanceof RequiredConstraintsViolated) {
                throw new TokenExpiredException('Token validation failed', 0, new \Exception($e->getMessage(), (int) $e->getCode(), $e));
            }
            throw new TokenInvalidException('Token parsing failed', 0, new \Exception($e->getMessage(), (int) $e->getCode(), $e));
        }
    }

    /**
     * Parses token without validation (for revocation).
     */
    public function parseToken(string $tokenString): UnencryptedToken
    {
        if (empty($tokenString)) {
            throw new TokenInvalidException('Token cannot be empty');
        }

        $token = $this->jwtConfiguration->parser()->parse($tokenString);

        if (!$token instanceof UnencryptedToken) {
            throw new TokenInvalidException('Invalid token format');
        }

        return $token;
    }

    /**
     * Parses a token without validation.
     */
    public function parseTokenWithoutValidation(string $tokenString): UnencryptedToken
    {
        if (empty($tokenString)) {
            throw new TokenInvalidException('Token cannot be empty');
        }

        $token = $this->jwtConfiguration->parser()->parse($tokenString);

        if (!$token instanceof UnencryptedToken) {
            throw new TokenInvalidException('Invalid token format');
        }

        return $token;
    }

    /**
     * Creates a JwtPayload from a token.
     */
    public function createPayloadFromToken(UnencryptedToken $token): JwtPayload
    {
        $claims = $token->claims()->all();

        $iat = $claims[RegisteredClaims::ISSUED_AT] ?? null;
        $exp = $claims[RegisteredClaims::EXPIRATION_TIME] ?? null;

        $issuedAt = $iat instanceof \DateTimeImmutable ? $iat->getTimestamp() : (int) $iat;
        $expiresAt = $exp instanceof \DateTimeImmutable ? $exp->getTimestamp() : (int) $exp;

        $standardClaims = [
            RegisteredClaims::SUBJECT, RegisteredClaims::ISSUED_AT, RegisteredClaims::EXPIRATION_TIME,
            RegisteredClaims::ID, RegisteredClaims::ISSUER, RegisteredClaims::AUDIENCE,
            RegisteredClaims::NOT_BEFORE, 'type',
        ];
        $customClaims = array_diff_key($claims, array_flip($standardClaims));

        return new JwtPayload(
            subject: (string) ($claims[RegisteredClaims::SUBJECT] ?? ''),
            issuedAt: $issuedAt,
            expiresAt: $expiresAt,
            jwtId: (string) ($claims[RegisteredClaims::ID] ?? ''),
            customClaims: $customClaims
        );
    }

    /**
     * Validates the token.
     */
    private function validateToken(UnencryptedToken $token): void
    {
        $constraints = [
            new SignedWith($this->jwtConfiguration->signer(), $this->jwtConfiguration->verificationKey()),
            new StrictValidAt($this->createClock()),
        ];

        $issuer = $this->config->getIssuer();
        $audience = $this->config->getConfig()['audience'] ?? null;

        if (!empty($issuer)) {
            $constraints[] = new IssuedBy($issuer);
        }

        if (!empty($audience)) {
            $constraints[] = new PermittedFor($audience);
        }

        $this->jwtConfiguration->validator()->assert($token, ...$constraints);
    }

    /**
     * Creates a clock instance for validation.
     */
    private function createClock(): ClockInterface
    {
        return new class() implements ClockInterface {
            public function now(): \DateTimeImmutable
            {
                return new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
            }
        };
    }
}
