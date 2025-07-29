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

namespace Zotenme\JwtAuth\Tests\Unit\DTO;

use Zotenme\JwtAuth\DTO\TokenPair;
use Zotenme\JwtAuth\Tests\TestCase;

/**
 * @internal
 *
 * @coversNothing
 */
class TokenPairTest extends TestCase
{
    private TokenPair $tokenPair;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tokenPair = new TokenPair(
            accessToken: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.access',
            refreshToken: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.refresh',
            accessExpiresIn: 900,
            refreshExpiresIn: 604800
        );
    }

    public function testConstructorAndProperties(): void
    {
        $this->assertSame('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.access', $this->tokenPair->accessToken);
        $this->assertSame('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.refresh', $this->tokenPair->refreshToken);
        $this->assertSame(900, $this->tokenPair->accessExpiresIn);
        $this->assertSame(604800, $this->tokenPair->refreshExpiresIn);
    }

    public function testToArray(): void
    {
        $expected = [
            'access_token' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.access',
            'refresh_token' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.refresh',
            'access_expires_in' => 900,
            'refresh_expires_in' => 604800,
        ];

        $this->assertSame($expected, $this->tokenPair->toArray());
    }

    public function testToArrayWithEmptyTokens(): void
    {
        $tokenPair = new TokenPair('', '', 0, 0);

        $expected = [
            'access_token' => '',
            'refresh_token' => '',
            'access_expires_in' => 0,
            'refresh_expires_in' => 0,
        ];

        $this->assertSame($expected, $tokenPair->toArray());
    }
}
