# Hyperf JWT Authentication

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.3-blue.svg)](https://php.net/)
[![Hyperf Version](https://img.shields.io/badge/hyperf-%5E3.1-green.svg)](https://hyperf.io/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![PHPStan](https://img.shields.io/badge/phpstan-level%208-brightgreen.svg)]()

A comprehensive JWT (JSON Web Token) authentication package for the Hyperf framework with advanced features like token rotation, blacklisting, SSO mode, and multiple algorithm support.

## Features

- 🔐 **Multiple Algorithm Support** - HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
- 🔄 **Token Rotation** - Automatic refresh token rotation for enhanced security
- 🚫 **Token Blacklisting** - Revoke tokens before expiration with grace period support
- 👤 **Single Sign-On (SSO)** - Limit users to one active session
- ⚡ **High Performance** - Built-in caching with Hyperf cache system
- 🛡️ **Type Safe** - Full PHP 8.3+ type declarations with PHPStan level 8

## Quick Start

### Installation

```bash
composer require zotenme/hyperf-jwt-auth
php bin/hyperf.php vendor:publish zotenme/hyperf-jwt-auth
```

### Basic Usage

```php
<?php

use Zotenme\JwtAuth\Contract\JwtManagerInterface;

class AuthController
{
    public function __construct(
        private JwtManagerInterface $jwtManager
    ) {}

    public function login(LoginRequest $request): JsonResponse
    {
        $userId = $this->validateCredentials($request);
        
        $tokenPair = $this->jwtManager->generateTokenPair(
            subjectId: $userId,
            payload: ['role' => 'user', 'permissions' => ['read', 'write']]
        );

        return new JsonResponse([
            'access_token' => $tokenPair->accessToken,
            'refresh_token' => $tokenPair->refreshToken,
            'expires_in' => $tokenPair->accessExpiresIn,
        ]);
    }

    public function refresh(RefreshRequest $request): JsonResponse
    {
        $refreshToken = $request->input('refresh_token');
        $tokenPair = $this->jwtManager->refreshAccessToken($refreshToken);

        return new JsonResponse([
            'access_token' => $tokenPair->accessToken,
            'refresh_token' => $tokenPair->refreshToken,
            'expires_in' => $tokenPair->accessExpiresIn,
        ]);
    }
}
```

### Configuration

Edit `config/autoload/jwt.php`:

```php
<?php

return [
    'algorithm' => 'HS256',
    'keys' => [
        'secret_key' => env('JWT_SECRET', 'your-secret-key-change-this'),
    ],
    'access_token' => ['ttl' => 900],  // 15 minutes
    'refresh_token' => ['ttl' => 604800], // 7 days
    'blacklist' => ['enabled' => true],
    'sso_mode' => false,
];
```

## Documentation

- 📖 [**Installation & Configuration**](docs/installation.md) - Complete setup guide
- 🚀 [**Usage Examples**](docs/usage.md) - Practical examples and patterns
- 🔧 [**API Reference**](docs/api-reference.md) - Complete API documentation
- 🛡️ [**Security Guide**](docs/security.md) - Best practices and security considerations
- 🏗️ [**Advanced Features**](docs/advanced.md) - Token rotation, SSO, RSA/ECDSA algorithms
- 🔌 [**Middleware Integration**](docs/middleware.md) - HTTP middleware setup
- ⚠️ [**Error Handling**](docs/error-handling.md) - Exception handling guide

## Requirements

- PHP 8.3 or higher
- Hyperf 3.1 or higher
- ext-json

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows PSR-12 coding standards and includes tests.

## Testing

```bash
# Run all tests
composer test

# Static analysis
composer analyse

# Code style fixer
composer cs-fix
```

## License

This package is open-sourced software licensed under the [MIT license](LICENSE).

## Support

If you discover any security vulnerabilities or have questions, please email zotenme@gmail.com.
