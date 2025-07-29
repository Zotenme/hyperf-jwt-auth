# Installation & Configuration

## System Requirements

- PHP 8.3 or higher
- Hyperf 3.1 or higher
- ext-json

## Installation

### Step 1: Install via Composer

```bash
composer require zotenme/hyperf-jwt-auth
```

### Step 2: Publish Configuration

```bash
php bin/hyperf.php vendor:publish zotenme/hyperf-jwt-auth
```

This will create `config/autoload/jwt.php` configuration file.

## Configuration

### Basic Configuration

The configuration file `config/autoload/jwt.php` contains all JWT settings:

```php
<?php

return [
    // JWT Algorithm
    'algorithm' => 'HS256',

    // Signing keys
    'keys' => [
        'secret_key' => env('JWT_SECRET', 'your-secret-key-change-this-in-production'),
        'private_key' => env('JWT_PRIVATE_KEY'), // For RSA/ECDSA
        'public_key' => env('JWT_PUBLIC_KEY'),   // For RSA/ECDSA
        'passphrase' => env('JWT_PASSPHRASE'),   // Optional
    ],

    // Token lifetimes
    'access_token' => [
        'ttl' => 900, // 15 minutes
    ],

    'refresh_token' => [
        'ttl' => 604800, // 7 days
        'rotation_enabled' => false,
    ],

    // Caching
    'cache' => [
        'prefix' => 'jwt_auth:',
        'ttl' => null, // Use token TTL if null
    ],

    // Token blacklisting
    'blacklist' => [
        'enabled' => true,
        'grace_period' => 0, // Seconds
    ],

    // Single Sign-On
    'sso_mode' => false,

    // Token issuer
    'issuer' => env('JWT_ISSUER', 'your-app-name'),
];
```

### Environment Variables

Add these variables to your `.env` file:

```env
JWT_SECRET=your-very-long-random-secret-key-here
JWT_ISSUER=your-app-name

# For RSA/ECDSA algorithms
JWT_PRIVATE_KEY=/path/to/private.pem
JWT_PUBLIC_KEY=/path/to/public.pem
JWT_PASSPHRASE=optional-passphrase
```

### Algorithm Configuration

#### HMAC Algorithms (Symmetric)

For HS256, HS384, HS512 - only secret key is required:

```php
'algorithm' => 'HS256',
'keys' => [
    'secret_key' => 'your-256-bit-secret',
],
```

#### RSA Algorithms (Asymmetric)

For RS256, RS384, RS512:

```php
'algorithm' => 'RS256',
'keys' => [
    'private_key' => '/path/to/private.pem',
    'public_key' => '/path/to/public.pem',
    'passphrase' => 'optional-passphrase',
],
```

Generate RSA keys:
```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem
```

#### ECDSA Algorithms (Asymmetric)

For ES256, ES384, ES512:

```php
'algorithm' => 'ES256',
'keys' => [
    'private_key' => '/path/to/ec-private.pem',
    'public_key' => '/path/to/ec-public.pem',
],
```

Generate ECDSA keys:
```bash
# Generate private key
openssl ecparam -genkey -name secp256r1 -noout -out ec-private.pem

# Extract public key
openssl ec -in ec-private.pem -pubout -out ec-public.pem
```

### Cache Configuration

The package uses Hyperf's cache system. Configure your cache driver in `config/autoload/cache.php`:

```php
return [
    'default' => [
        'driver' => 'redis',
        'packer' => 'php',
        'prefix' => 'hyperf:cache:',
    ],
];
```

### Service Registration

The package automatically registers services via `ConfigProvider`. No manual registration needed.

### Validation

After configuration, validate your setup:

```php
<?php

use Zotenme\JwtAuth\Contract\JwtManagerInterface;

// In a controller or service
public function testConfiguration(JwtManagerInterface $jwtManager): void
{
    try {
        $tokenPair = $jwtManager->generateTokenPair('test-user');
        $payload = $jwtManager->validateAccessToken($tokenPair->accessToken);
        echo "Configuration is valid!";
    } catch (\Exception $e) {
        echo "Configuration error: " . $e->getMessage();
    }
}
```
