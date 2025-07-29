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

namespace Zotenme\JwtAuth\Tests\Unit\Service;

use Hyperf\Cache\CacheManager;
use Hyperf\Cache\Driver\DriverInterface;
use Mockery\MockInterface;
use Zotenme\JwtAuth\Config\JwtConfig;
use Zotenme\JwtAuth\Service\TokenStorage;
use Zotenme\JwtAuth\Tests\TestCase;

/**
 * @internal
 *
 * @coversNothing
 */
class TokenStorageTest extends TestCase
{
    private TokenStorage $tokenStorage;

    /** @var DriverInterface&MockInterface */
    private DriverInterface $cache;

    private JwtConfig $jwtConfig;

    protected function setUp(): void
    {
        parent::setUp();

        $this->cache = \Mockery::mock(DriverInterface::class);

        $cacheManager = \Mockery::mock(CacheManager::class);
        $cacheManager->shouldReceive('getDriver')
            ->with('default')
            ->andReturn($this->cache);

        $config = $this->createMockConfig();
        $this->jwtConfig = new JwtConfig($config);

        $this->tokenStorage = new TokenStorage($cacheManager, $config, $this->jwtConfig);
    }

    public function testSetCallsCacheSet(): void
    {
        $this->cache->shouldReceive('set')
            ->with('test-key', 'test-value', 3600)
            ->once()
            ->andReturn(true);

        $result = $this->tokenStorage->set('test-key', 'test-value', 3600);
        $this->assertTrue($result);
    }

    public function testGetCallsCacheGet(): void
    {
        $this->cache->shouldReceive('get')
            ->with('test-key', 'default')
            ->once()
            ->andReturn('cached-value');

        $result = $this->tokenStorage->get('test-key', 'default');
        $this->assertSame('cached-value', $result);
    }

    public function testDeleteCallsCacheDelete(): void
    {
        $this->cache->shouldReceive('delete')
            ->with('test-key')
            ->once()
            ->andReturn(true);

        $result = $this->tokenStorage->delete('test-key');
        $this->assertTrue($result);
    }

    public function testExistsCallsCacheHas(): void
    {
        $this->cache->shouldReceive('has')
            ->with('test-key')
            ->once()
            ->andReturn(true);

        $result = $this->tokenStorage->exists('test-key');
        $this->assertTrue($result);
    }

    public function testRevokeTokenSkipsWhenBlacklistDisabled(): void
    {
        $config = $this->createMockConfig(['jwt.blacklist.enabled' => false]);
        $jwtConfig = new JwtConfig($config);

        /** @var CacheManager&MockInterface $cacheManager */
        $cacheManager = \Mockery::mock(CacheManager::class);
        $cacheManager->shouldReceive('getDriver')->andReturn($this->cache);

        $tokenStorage = new TokenStorage($cacheManager, $config, $jwtConfig);

        // Should not call set when blacklist is disabled
        $this->cache->shouldNotReceive('set');

        $tokenStorage->revokeToken('test-jti', 3600);
        $this->assertTrue(true); // Ensure we have an assertion
    }

    public function testIsTokenRevokedReturnsFalseWhenBlacklistDisabled(): void
    {
        $config = $this->createMockConfig(['jwt.blacklist.enabled' => false]);
        $jwtConfig = new JwtConfig($config);

        /** @var CacheManager&MockInterface $cacheManager */
        $cacheManager = \Mockery::mock(CacheManager::class);
        $cacheManager->shouldReceive('getDriver')->andReturn($this->cache);

        $tokenStorage = new TokenStorage($cacheManager, $config, $jwtConfig);

        // Should not call get when blacklist is disabled
        $this->cache->shouldNotReceive('get');

        $result = $tokenStorage->isTokenRevoked('test-jti');
        $this->assertFalse($result);
    }

    public function testIsSsoModeEnabled(): void
    {
        $this->assertFalse($this->tokenStorage->isSsoModeEnabled());

        $config = $this->createMockConfig(['jwt.sso_mode' => true]);
        $jwtConfig = new JwtConfig($config);

        /** @var CacheManager&MockInterface $cacheManager */
        $cacheManager = \Mockery::mock(CacheManager::class);
        $cacheManager->shouldReceive('getDriver')->andReturn($this->cache);

        $tokenStorage = new TokenStorage($cacheManager, $config, $jwtConfig);
        $this->assertTrue($tokenStorage->isSsoModeEnabled());
    }

    public function testCleanup(): void
    {
        // cleanup() method should not throw any exceptions
        $this->expectNotToPerformAssertions();
        $this->tokenStorage->cleanup();
    }
}
