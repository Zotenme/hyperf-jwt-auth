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

namespace Zotenme\JwtAuth\Tests;

use Hyperf\Contract\ConfigInterface;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\SimpleCache\CacheInterface;

abstract class TestCase extends BaseTestCase
{
    protected function tearDown(): void
    {
        \Mockery::close();
        parent::tearDown();
    }

    /**
     * Create a mock config with JWT settings.
     *
     * @param array<string, mixed> $config
     */
    protected function createMockConfig(array $config = []): ConfigInterface
    {
        $defaultConfig = [
            'jwt.algorithm' => 'HS256',
            'jwt.keys.secret_key' => 'test-secret-key-for-testing-purposes-only',
            'jwt.keys.private_key' => null,
            'jwt.keys.public_key' => null,
            'jwt.keys.passphrase' => '',
            'jwt.access_token.ttl' => 900,
            'jwt.refresh_token.ttl' => 604800,
            'jwt.refresh_token.rotation_enabled' => false,
            'jwt.cache.prefix' => 'jwt_test:',
            'jwt.cache.ttl' => null,
            'jwt.blacklist.enabled' => true,
            'jwt.blacklist.grace_period' => 0,
            'jwt.sso_mode' => false,
            'jwt.issuer' => 'test-issuer',
        ];

        $mergedConfig = array_merge($defaultConfig, $config);

        $mock = \Mockery::mock(ConfigInterface::class);

        foreach ($mergedConfig as $key => $value) {
            $mock->shouldReceive('get')
                ->with($key, \Mockery::any())
                ->andReturn($value);
        }

        // Handle get calls without default values
        $mock->shouldReceive('get')
            ->andReturnUsing(function ($key, $default = null) use ($mergedConfig) {
                return $mergedConfig[$key] ?? $default;
            });

        /* @var ConfigInterface&\Mockery\MockInterface $mock */
        return $mock;
    }

    /**
     * Create a mock cache interface.
     */
    protected function createMockCache(): CacheInterface
    {
        $cache = \Mockery::mock(CacheInterface::class);

        $cache->shouldReceive('get')
            ->andReturn(null);

        $cache->shouldReceive('set')
            ->andReturn(true);

        $cache->shouldReceive('delete')
            ->andReturn(true);

        $cache->shouldReceive('has')
            ->andReturn(false);

        /* @var CacheInterface&\Mockery\MockInterface $cache */
        return $cache;
    }

    /**
     * Get test JWT configuration array.
     *
     * @return array<string, mixed>
     */
    protected function getTestJwtConfig(): array
    {
        return [
            'algorithm' => 'HS256',
            'keys' => [
                'secret_key' => 'test-secret-key-for-testing-purposes-only',
                'private_key' => null,
                'public_key' => null,
                'passphrase' => '',
            ],
            'access_token' => [
                'ttl' => 900,
            ],
            'refresh_token' => [
                'ttl' => 604800,
                'rotation_enabled' => false,
            ],
            'cache' => [
                'prefix' => 'jwt_test:',
                'ttl' => null,
            ],
            'blacklist' => [
                'enabled' => true,
                'grace_period' => 0,
            ],
            'sso_mode' => false,
            'issuer' => 'test-issuer',
        ];
    }
}
