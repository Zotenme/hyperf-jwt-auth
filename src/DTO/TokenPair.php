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

/**
 * DTO for token pair (access + refresh).
 */
readonly class TokenPair
{
    /**
     * @param string $accessToken      Access token
     * @param string $refreshToken     Refresh token
     * @param int    $accessExpiresIn  Access token lifetime in seconds
     * @param int    $refreshExpiresIn Refresh token lifetime in seconds
     */
    public function __construct(
        public string $accessToken,
        public string $refreshToken,
        public int $accessExpiresIn,
        public int $refreshExpiresIn
    ) {}

    /**
     * Converts to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'access_token' => $this->accessToken,
            'refresh_token' => $this->refreshToken,
            'access_expires_in' => $this->accessExpiresIn,
            'refresh_expires_in' => $this->refreshExpiresIn,
        ];
    }
}
