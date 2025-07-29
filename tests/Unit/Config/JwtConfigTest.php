<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Tests\Unit\Config;

use Zotenme\JwtAuth\Config\JwtAlgorithm;
use Zotenme\JwtAuth\Config\JwtConfig;
use Zotenme\JwtAuth\Exception\JwtException;
use Zotenme\JwtAuth\Tests\TestCase;

class JwtConfigTest extends TestCase
{
    private JwtConfig $config;

    protected function setUp(): void
    {
        parent::setUp();
        $mockConfig = $this->createMockConfig();
        $this->config = new JwtConfig($mockConfig);
    }

    public function testGetAlgorithm(): void
    {
        $algorithm = $this->config->getAlgorithm();
        $this->assertInstanceOf(JwtAlgorithm::class, $algorithm);
        $this->assertSame('HS256', $algorithm->value);
    }

    public function testGetAlgorithmWithUnsupportedAlgorithm(): void
    {
        $mockConfig = $this->createMockConfig(['jwt.algorithm' => 'INVALID']);
        $config = new JwtConfig($mockConfig);

        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Unsupported algorithm: INVALID');
        $config->getAlgorithm();
    }

    public function testGetSecretKey(): void
    {
        $secretKey = $this->config->getSecretKey();
        $this->assertSame('test-secret-key-for-testing-purposes-only', $secretKey);
    }

    public function testGetSecretKeyEmpty(): void
    {
        $mockConfig = $this->createMockConfig(['jwt.keys.secret_key' => '']);
        $config = new JwtConfig($mockConfig);

        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Secret key is not configured');
        $config->getSecretKey();
    }

    public function testGetPrivateKey(): void
    {
        $privateKey = 'test-private-key';
        $mockConfig = $this->createMockConfig(['jwt.keys.private_key' => $privateKey]);
        $config = new JwtConfig($mockConfig);

        $this->assertSame($privateKey, $config->getPrivateKey());
    }

    public function testGetPrivateKeyEmpty(): void
    {
        $mockConfig = $this->createMockConfig(['jwt.keys.private_key' => '']);
        $config = new JwtConfig($mockConfig);

        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Private key is not configured');
        $config->getPrivateKey();
    }

    public function testGetPublicKey(): void
    {
        $publicKey = 'test-public-key';
        $mockConfig = $this->createMockConfig(['jwt.keys.public_key' => $publicKey]);
        $config = new JwtConfig($mockConfig);

        $this->assertSame($publicKey, $config->getPublicKey());
    }

    public function testGetPublicKeyEmpty(): void
    {
        $mockConfig = $this->createMockConfig(['jwt.keys.public_key' => '']);
        $config = new JwtConfig($mockConfig);

        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Public key is not configured');
        $config->getPublicKey();
    }

    public function testGetPassphrase(): void
    {
        $passphrase = $this->config->getPassphrase();
        $this->assertSame('', $passphrase);

        $mockConfig = $this->createMockConfig(['jwt.keys.passphrase' => 'test-passphrase']);
        $config = new JwtConfig($mockConfig);
        $this->assertSame('test-passphrase', $config->getPassphrase());
    }

    public function testGetAccessTokenTtl(): void
    {
        $ttl = $this->config->getAccessTokenTtl();
        $this->assertSame(900, $ttl);
    }

    public function testGetRefreshTokenTtl(): void
    {
        $ttl = $this->config->getRefreshTokenTtl();
        $this->assertSame(604800, $ttl);
    }

    public function testIsRefreshTokenRotationEnabled(): void
    {
        $this->assertFalse($this->config->isRefreshTokenRotationEnabled());

        $mockConfig = $this->createMockConfig(['jwt.refresh_token.rotation_enabled' => true]);
        $config = new JwtConfig($mockConfig);
        $this->assertTrue($config->isRefreshTokenRotationEnabled());
    }

    public function testGetCachePrefix(): void
    {
        $prefix = $this->config->getCachePrefix();
        $this->assertSame('jwt_test:', $prefix);
    }

    public function testGetCacheTtl(): void
    {
        $ttl = $this->config->getCacheTtl();
        $this->assertNull($ttl);

        $mockConfig = $this->createMockConfig(['jwt.cache.ttl' => 3600]);
        $config = new JwtConfig($mockConfig);
        $this->assertSame(3600, $config->getCacheTtl());
    }

    public function testIsBlacklistEnabled(): void
    {
        $this->assertTrue($this->config->isBlacklistEnabled());

        $mockConfig = $this->createMockConfig(['jwt.blacklist.enabled' => false]);
        $config = new JwtConfig($mockConfig);
        $this->assertFalse($config->isBlacklistEnabled());
    }

    public function testGetBlacklistGracePeriod(): void
    {
        $gracePeriod = $this->config->getBlacklistGracePeriod();
        $this->assertSame(0, $gracePeriod);

        $mockConfig = $this->createMockConfig(['jwt.blacklist.grace_period' => 60]);
        $config = new JwtConfig($mockConfig);
        $this->assertSame(60, $config->getBlacklistGracePeriod());
    }

    public function testIsSsoModeEnabled(): void
    {
        $this->assertFalse($this->config->isSsoModeEnabled());

        $mockConfig = $this->createMockConfig(['jwt.sso_mode' => true]);
        $config = new JwtConfig($mockConfig);
        $this->assertTrue($config->isSsoModeEnabled());
    }

    public function testGetIssuer(): void
    {
        $issuer = $this->config->getIssuer();
        $this->assertSame('test-issuer', $issuer);
    }

    public function testValidateKeysForSymmetricAlgorithm(): void
    {
        $this->expectNotToPerformAssertions();
        $this->config->validateKeys();
    }

    public function testValidateKeysForAsymmetricAlgorithm(): void
    {
        $mockConfig = $this->createMockConfig([
            'jwt.algorithm' => 'RS256',
            'jwt.keys.private_key' => 'test-private-key',
            'jwt.keys.public_key' => 'test-public-key',
        ]);
        $config = new JwtConfig($mockConfig);

        $this->expectNotToPerformAssertions();
        $config->validateKeys();
    }

    public function testValidateKeysFailsForMissingSecretKey(): void
    {
        $mockConfig = $this->createMockConfig(['jwt.keys.secret_key' => '']);
        $config = new JwtConfig($mockConfig);

        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Secret key is not configured');
        $config->validateKeys();
    }
}
