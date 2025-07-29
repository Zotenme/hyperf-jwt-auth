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

namespace Zotenme\JwtAuth\Tests\Unit\Factory;

use Lcobucci\JWT\Configuration;
use Zotenme\JwtAuth\Config\JwtConfig;
use Zotenme\JwtAuth\Factory\JwtConfigurationFactory;
use Zotenme\JwtAuth\Tests\TestCase;

/**
 * @internal
 *
 * @coversNothing
 */
class JwtConfigurationFactoryTest extends TestCase
{
    private JwtConfigurationFactory $factory;

    private JwtConfig $config;

    protected function setUp(): void
    {
        parent::setUp();

        $mockConfig = $this->createMockConfig();
        $this->config = new JwtConfig($mockConfig);
        $this->factory = new JwtConfigurationFactory($this->config);
    }

    public function testCreateSymmetricConfiguration(): void
    {
        $configuration = $this->factory->create();

        $this->assertInstanceOf(Configuration::class, $configuration);
        $this->assertNotNull($configuration->signer());
        $this->assertNotNull($configuration->signingKey());
        $this->assertNotNull($configuration->verificationKey());
    }

    public function testCreateAsymmetricConfiguration(): void
    {
        $mockConfig = $this->createMockConfig([
            'jwt.algorithm' => 'RS256',
            'jwt.keys.private_key' => $this->generateRsaPrivateKey(),
            'jwt.keys.public_key' => $this->generateRsaPublicKey(),
        ]);

        $config = new JwtConfig($mockConfig);
        $factory = new JwtConfigurationFactory($config);

        $configuration = $factory->create();

        $this->assertInstanceOf(Configuration::class, $configuration);
        $this->assertNotNull($configuration->signer());
        $this->assertNotNull($configuration->signingKey());
        $this->assertNotNull($configuration->verificationKey());
    }

    private function generateRsaPrivateKey(): string
    {
        return '-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wjnD6wG0ZbTHDw2LYXIHq3PL4IrH3U8+SgKlVOZT9+Kt5cHWPzB3X8pW7NbG7Y1c
-----END PRIVATE KEY-----';
    }

    private function generateRsaPublicKey(): string
    {
        return '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1L7VLPHCgcI5w+sB
tGW0xw8Ni2FyB6tzy+CKx91PPkoCpVTmU/fireXB1j8wd1/KVuzWxu2NXA==
-----END PUBLIC KEY-----';
    }
}
