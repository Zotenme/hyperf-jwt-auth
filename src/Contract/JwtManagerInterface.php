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

namespace Zotenme\JwtAuth\Contract;

use Zotenme\JwtAuth\DTO\JwtPayload;
use Zotenme\JwtAuth\DTO\TokenPair;

/**
 * Main interface for working with JWT tokens.
 */
interface JwtManagerInterface
{
    /**
     * Generates a token pair (access + refresh).
     *
     * @param array<string, mixed> $payload
     */
    public function generateTokenPair(string $subjectId, array $payload = []): TokenPair;

    /**
     * Refreshes the access token using the refresh token.
     */
    public function refreshAccessToken(string $refreshToken): TokenPair;

    /**
     * Validates the access token.
     */
    public function validateAccessToken(string $accessToken): JwtPayload;

    /**
     * Validates the refresh token.
     */
    public function validateRefreshToken(string $refreshToken): JwtPayload;

    /**
     * Revokes a token (adds to blacklist).
     */
    public function revokeToken(string $token): void;

    /**
     * Revokes all tokens for a specific subject.
     */
    public function revokeAllSubjectTokens(string $subjectId): void;
}
