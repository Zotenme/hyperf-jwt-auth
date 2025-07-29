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
- 🧪 **Well Tested** - 100% test coverage with comprehensive unit tests
- 📦 **Easy Integration** - Simple configuration and middleware setup

## Requirements

- PHP 8.3 or higher
- Hyperf 3.1 or higher
- ext-json

## Installation

Install the package via Composer:

```bash
composer require zotenme/hyperf-jwt-auth
```

Publish the configuration file:

```bash
php bin/hyperf.php vendor:publish zotenme/hyperf-jwt-auth
```

## Configuration

After publishing, edit `config/autoload/jwt.php`:

```php
<?php

return [
    // JWT Algorithm (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512)
    'algorithm' => 'HS256',

    // Keys for signing and verification
    'keys' => [
        'secret_key' => env('JWT_SECRET', 'your-secret-key-change-this-in-production'),
        'private_key' => env('JWT_PRIVATE_KEY'), // For RSA/ECDSA algorithms
        'public_key' => env('JWT_PUBLIC_KEY'),   // For RSA/ECDSA algorithms
        'passphrase' => env('JWT_PASSPHRASE'),   // Optional passphrase for private key
    ],

    // Access token settings
    'access_token' => [
        'ttl' => 900, // 15 minutes
    ],

    // Refresh token settings
    'refresh_token' => [
        'ttl' => 604800, // 7 days
        'rotation_enabled' => false, // Enable automatic token rotation
    ],

    // Cache settings
    'cache' => [
        'prefix' => 'jwt_auth:',
        'ttl' => null, // Use token TTL if null
    ],

    // Token blacklisting
    'blacklist' => [
        'enabled' => true,
        'grace_period' => 0, // Seconds
    ],

    // Single Sign-On mode
    'sso_mode' => false, // Only one active session per user

    // Token issuer
    'issuer' => env('JWT_ISSUER', 'your-app-name'),
];
```

## Basic Usage

### Generate Token Pair

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
        // Validate credentials...
        $userId = $this->validateCredentials($request);
        
        // Generate tokens
        $tokenPair = $this->jwtManager->generateTokenPair(
            subjectId: $userId,
            payload: [
                'role' => 'user',
                'permissions' => ['read', 'write'],
                'email' => 'user@example.com'
            ]
        );

        return new JsonResponse([
            'access_token' => $tokenPair->accessToken,
            'refresh_token' => $tokenPair->refreshToken,
            'expires_in' => $tokenPair->accessExpiresIn,
        ]);
    }
}
```

### Validate Access Token

```php
<?php

use Zotenme\JwtAuth\Contract\JwtManagerInterface;
use Zotenme\JwtAuth\Exception\TokenExpiredException;
use Zotenme\JwtAuth\Exception\TokenInvalidException;

class UserController
{
    public function __construct(
        private JwtManagerInterface $jwtManager
    ) {}

    public function getProfile(string $token): JsonResponse
    {
        try {
            $payload = $this->jwtManager->validateAccessToken($token);
            
            return new JsonResponse([
                'user_id' => $payload->subject,
                'role' => $payload->getClaim('role'),
                'permissions' => $payload->getClaim('permissions'),
                'expires_at' => $payload->expiresAt,
            ]);
        } catch (TokenExpiredException $e) {
            return new JsonResponse(['error' => 'Token expired'], 401);
        } catch (TokenInvalidException $e) {
            return new JsonResponse(['error' => 'Invalid token'], 401);
        }
    }
}
```

### Refresh Access Token

```php
<?php

public function refresh(RefreshRequest $request): JsonResponse
{
    try {
        $refreshToken = $request->input('refresh_token');
        $tokenPair = $this->jwtManager->refreshAccessToken($refreshToken);

        return new JsonResponse([
            'access_token' => $tokenPair->accessToken,
            'refresh_token' => $tokenPair->refreshToken,
            'expires_in' => $tokenPair->accessExpiresIn,
        ]);
    } catch (TokenExpiredException $e) {
        return new JsonResponse(['error' => 'Refresh token expired'], 401);
    }
}
```

### Revoke Token

```php
<?php

public function logout(LogoutRequest $request): JsonResponse
{
    $token = $request->input('token');
    
    // Revoke the token (add to blacklist)
    $this->jwtManager->revokeToken($token);

    return new JsonResponse(['message' => 'Successfully logged out']);
}
```

## Middleware Integration

Create a JWT authentication middleware:

```php
<?php

declare(strict_types=1);

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zotenme\JwtAuth\Contract\JwtManagerInterface;
use Zotenme\JwtAuth\Exception\TokenInvalidException;

class JwtAuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private JwtManagerInterface $jwtManager
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->extractToken($request);

        if ($token === null) {
            throw new TokenInvalidException('Missing authorization token');
        }

        $payload = $this->jwtManager->validateAccessToken($token);

        // Add JWT data to request attributes
        $request = $request
            ->withAttribute('jwt_payload', $payload)
            ->withAttribute('user_id', $payload->subject)
            ->withAttribute('jwt_claims', $payload->customClaims);

        return $handler->handle($request);
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        $authHeader = $request->getHeaderLine('Authorization');
        
        if (str_starts_with($authHeader, 'Bearer ')) {
            return substr($authHeader, 7);
        }

        return null;
    }
}
```

Register the middleware in `config/autoload/middlewares.php`:

```php
<?php

return [
    'http' => [
        App\Middleware\JwtAuthMiddleware::class,
    ],
];
```

## Advanced Features

### Token Rotation

Enable automatic refresh token rotation for enhanced security:

```php
// config/autoload/jwt.php
'refresh_token' => [
    'ttl' => 604800,
    'rotation_enabled' => true, // New refresh token on each refresh
],
```

### Single Sign-On Mode

Limit users to one active session:

```php
// config/autoload/jwt.php
'sso_mode' => true, // Revoke old tokens when generating new ones
```

### RSA/ECDSA Algorithms

For asymmetric algorithms, generate key pairs:

```bash
# Generate RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Generate ECDSA key pair
openssl ecparam -genkey -name secp256r1 -noout -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem
```

Configure in `config/autoload/jwt.php`:

```php
'algorithm' => 'RS256', // or ES256
'keys' => [
    'private_key' => '/path/to/private.pem',
    'public_key' => '/path/to/public.pem',
    'passphrase' => 'optional-passphrase',
],
```

### Custom Claims

Add custom data to tokens:

```php
$tokenPair = $this->jwtManager->generateTokenPair(
    subjectId: 'user-123',
    payload: [
        'role' => 'admin',
        'permissions' => ['read', 'write', 'delete'],
        'organization_id' => 'org-456',
        'metadata' => [
            'last_login' => time(),
            'ip_address' => '192.168.1.1',
        ],
    ]
);

// Access custom claims
$payload = $this->jwtManager->validateAccessToken($token);
$role = $payload->getClaim('role');
$permissions = $payload->getClaim('permissions');
$orgId = $payload->getClaim('organization_id');
```

## Error Handling

The package provides specific exceptions for different error cases:

```php
<?php

use Zotenme\JwtAuth\Exception\JwtException;
use Zotenme\JwtAuth\Exception\TokenExpiredException;
use Zotenme\JwtAuth\Exception\TokenInvalidException;
use Zotenme\JwtAuth\Exception\TokenBlacklistedException;

try {
    $payload = $this->jwtManager->validateAccessToken($token);
} catch (TokenExpiredException $e) {
    // Token has expired
    return response()->json(['error' => 'Token expired'], 401);
} catch (TokenBlacklistedException $e) {
    // Token has been revoked
    return response()->json(['error' => 'Token revoked'], 401);
} catch (TokenInvalidException $e) {
    // Token is malformed or invalid
    return response()->json(['error' => 'Invalid token'], 401);
} catch (JwtException $e) {
    // General JWT error
    return response()->json(['error' => 'Authentication error'], 401);
}
```

## API Reference

### JwtManagerInterface

#### `generateTokenPair(string $subjectId, array $payload = []): TokenPair`
Generates a new access and refresh token pair.

#### `refreshAccessToken(string $refreshToken): TokenPair`
Refreshes the access token using a refresh token.

#### `validateAccessToken(string $accessToken): JwtPayload`
Validates and parses an access token.

#### `validateRefreshToken(string $refreshToken): JwtPayload`
Validates and parses a refresh token.

#### `revokeToken(string $token): void`
Revokes a token by adding it to the blacklist.

### JwtPayload

#### Properties
- `string $subject` - Token subject (usually user ID)
- `int $issuedAt` - Token creation timestamp
- `int $expiresAt` - Token expiration timestamp
- `string $jwtId` - Unique token identifier
- `array $customClaims` - Additional custom claims

#### Methods
- `isExpired(): bool` - Check if token has expired
- `getClaim(string $key, mixed $default = null): mixed` - Get claim value

### TokenPair

#### Properties
- `string $accessToken` - The access token
- `string $refreshToken` - The refresh token
- `int $accessExpiresIn` - Access token TTL in seconds
- `int $refreshExpiresIn` - Refresh token TTL in seconds

#### Methods
- `toArray(): array` - Convert to array representation

## Testing

Run the test suite:

```bash
# Run all tests
composer test

# Run tests with coverage
composer test-coverage

# Run static analysis
composer analyse

# Run code style fixer
composer cs-fix
```

## Security Considerations

1. **Secret Key**: Use a strong, random secret key in production
2. **HTTPS**: Always use HTTPS in production to prevent token interception
3. **Token Storage**: Store tokens securely on the client side
4. **Rotation**: Enable token rotation for enhanced security
5. **Blacklisting**: Use token blacklisting for immediate revocation
6. **Short TTL**: Use short access token TTL (15-30 minutes)
7. **Refresh Tokens**: Store refresh tokens securely and rotate them

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows PSR-12 coding standards and includes tests.

## License

This package is open-sourced software licensed under the [MIT license](LICENSE).

## Support

If you discover any security vulnerabilities or have questions, please email zotenme@gmail.com.

## Changelog

### v1.0.0
- Initial release
- JWT token generation and validation
- Multiple algorithm support
- Token blacklisting
- SSO mode
- Token rotation
- Comprehensive test suite
