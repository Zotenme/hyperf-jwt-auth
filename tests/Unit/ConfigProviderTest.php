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

namespace Zotenme\JwtAuth\Tests\Unit;

use Zotenme\JwtAuth\ConfigProvider;
use Zotenme\JwtAuth\Contract\JwtManagerInterface;
use Zotenme\JwtAuth\Contract\TokenStorageInterface;
use Zotenme\JwtAuth\JwtManager;
use Zotenme\JwtAuth\Service\TokenStorage;
use Zotenme\JwtAuth\Tests\TestCase;

/**
 * @internal
 *
 * @coversNothing
 */
class ConfigProviderTest extends TestCase
{
    private ConfigProvider $configProvider;

    protected function setUp(): void
    {
        parent::setUp();
        $this->configProvider = new ConfigProvider();
    }

    public function testInvokeReturnsCorrectConfiguration(): void
    {
        $config = ($this->configProvider)();

        $this->assertIsArray($config);
        $this->assertArrayHasKey('dependencies', $config);
        $this->assertArrayHasKey('commands', $config);
        $this->assertArrayHasKey('annotations', $config);
        $this->assertArrayHasKey('publish', $config);
    }

    public function testDependenciesConfiguration(): void
    {
        $config = ($this->configProvider)();
        $dependencies = $config['dependencies'];

        $this->assertArrayHasKey(JwtManagerInterface::class, $dependencies);
        $this->assertArrayHasKey(TokenStorageInterface::class, $dependencies);
        $this->assertSame(JwtManager::class, $dependencies[JwtManagerInterface::class]);
        $this->assertSame(TokenStorage::class, $dependencies[TokenStorageInterface::class]);
    }

    public function testCommandsConfiguration(): void
    {
        $config = ($this->configProvider)();

        $this->assertIsArray($config['commands']);
        $this->assertEmpty($config['commands']);
    }

    public function testAnnotationsConfiguration(): void
    {
        $config = ($this->configProvider)();
        $annotations = $config['annotations'];

        $this->assertArrayHasKey('scan', $annotations);
        $this->assertArrayHasKey('paths', $annotations['scan']);
        $this->assertNotEmpty($annotations['scan']['paths']);
        // Проверяем что путь содержит src директорию
        $paths = $annotations['scan']['paths'];
        $this->assertTrue(count($paths) > 0);
        $this->assertStringEndsWith('/src', $paths[0]);
    }

    public function testPublishConfiguration(): void
    {
        $config = ($this->configProvider)();
        $publish = $config['publish'];

        $this->assertIsArray($publish);
        $this->assertCount(1, $publish);

        $jwtPublish = $publish[0];
        $this->assertArrayHasKey('id', $jwtPublish);
        $this->assertArrayHasKey('description', $jwtPublish);
        $this->assertArrayHasKey('source', $jwtPublish);
        $this->assertArrayHasKey('destination', $jwtPublish);

        $this->assertSame('jwt', $jwtPublish['id']);
        $this->assertSame('JWT Authentication configuration file.', $jwtPublish['description']);
        $this->assertStringEndsWith('/publish/jwt.php', $jwtPublish['source']);
        $this->assertSame('/config/autoload/jwt.php', $jwtPublish['destination']);
    }
}
