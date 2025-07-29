<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Tests\Unit\DTO;

use Lcobucci\JWT\Token\RegisteredClaims;
use Zotenme\JwtAuth\DTO\JwtPayload;
use Zotenme\JwtAuth\Tests\TestCase;

class JwtPayloadTest extends TestCase
{
    private JwtPayload $payload;

    protected function setUp(): void
    {
        parent::setUp();
        $this->payload = new JwtPayload(
            subject: 'user-123',
            issuedAt: time(),
            expiresAt: time() + 3600,
            jwtId: 'jwt-id-123',
            customClaims: ['role' => 'admin', 'permissions' => ['read', 'write']]
        );
    }

    public function testConstructorAndProperties(): void
    {
        $this->assertSame('user-123', $this->payload->subject);
        $this->assertSame('jwt-id-123', $this->payload->jwtId);
        $this->assertIsInt($this->payload->issuedAt);
        $this->assertIsInt($this->payload->expiresAt);
        $this->assertIsArray($this->payload->customClaims);
        $this->assertSame('admin', $this->payload->customClaims['role']);
    }

    public function testIsExpiredReturnsFalseForValidToken(): void
    {
        $payload = new JwtPayload(
            subject: 'user-123',
            issuedAt: time(),
            expiresAt: time() + 3600, // expires in 1 hour
            jwtId: 'jwt-id-123'
        );

        $this->assertFalse($payload->isExpired());
    }

    public function testIsExpiredReturnsTrueForExpiredToken(): void
    {
        $payload = new JwtPayload(
            subject: 'user-123',
            issuedAt: time() - 7200,
            expiresAt: time() - 3600, // expired 1 hour ago
            jwtId: 'jwt-id-123'
        );

        $this->assertTrue($payload->isExpired());
    }

    public function testGetClaimForStandardClaims(): void
    {
        $this->assertSame('user-123', $this->payload->getClaim('sub'));
        $this->assertSame('user-123', $this->payload->getClaim(RegisteredClaims::SUBJECT));
        $this->assertSame('jwt-id-123', $this->payload->getClaim('jti'));
        $this->assertSame('jwt-id-123', $this->payload->getClaim(RegisteredClaims::ID));
        $this->assertSame($this->payload->issuedAt, $this->payload->getClaim('iat'));
        $this->assertSame($this->payload->issuedAt, $this->payload->getClaim(RegisteredClaims::ISSUED_AT));
        $this->assertSame($this->payload->expiresAt, $this->payload->getClaim('exp'));
        $this->assertSame($this->payload->expiresAt, $this->payload->getClaim(RegisteredClaims::EXPIRATION_TIME));
    }

    public function testGetClaimForCustomClaims(): void
    {
        $this->assertSame('admin', $this->payload->getClaim('role'));
        $this->assertSame(['read', 'write'], $this->payload->getClaim('permissions'));
    }

    public function testGetClaimReturnsDefaultForNonExistentClaim(): void
    {
        $this->assertNull($this->payload->getClaim('non-existent'));
        $this->assertSame('default', $this->payload->getClaim('non-existent', 'default'));
        $this->assertSame(0, $this->payload->getClaim('non-existent', 0));
    }

    public function testGetClaimWithEmptyCustomClaims(): void
    {
        $payload = new JwtPayload(
            subject: 'user-123',
            issuedAt: time(),
            expiresAt: time() + 3600,
            jwtId: 'jwt-id-123'
        );

        $this->assertSame('user-123', $payload->getClaim('sub'));
        $this->assertNull($payload->getClaim('role'));
        $this->assertSame('guest', $payload->getClaim('role', 'guest'));
    }
}
