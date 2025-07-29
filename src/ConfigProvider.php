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

namespace Zotenme\JwtAuth;

use Zotenme\JwtAuth\Contract\JwtManagerInterface;
use Zotenme\JwtAuth\Contract\TokenStorageInterface;
use Zotenme\JwtAuth\Service\TokenStorage;

class ConfigProvider
{
    /**
     * @return array<string, mixed>
     */
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                // Main services registration
                JwtManagerInterface::class => JwtManager::class,
                TokenStorageInterface::class => TokenStorage::class,
            ],
            'commands' => [],
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__,
                    ],
                ],
            ],
            'publish' => [
                [
                    'id' => 'jwt',
                    'description' => 'JWT Authentication configuration file.',
                    'source' => __DIR__ . '/../publish/jwt.php',
                    'destination' => '/config/autoload/jwt.php',
                ],
            ],
        ];
    }
}
