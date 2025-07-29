<?php

declare(strict_types=1);

use function Hyperf\Support\env;

return [
    /*
    |--------------------------------------------------------------------------
    | JWT Algorithm
    |--------------------------------------------------------------------------
    |
    | Available symmetric algorithms: HS256, HS384, HS512
    | Available asymmetric algorithms: RS256, RS384, RS512, ES256, ES384, ES512
    | The default is HS256, which is a symmetric algorithm.
    |
    */
    'algorithm' => 'HS256',

    /*
    |--------------------------------------------------------------------------
    | JWT Keys
    |--------------------------------------------------------------------------
    |
    | Keys for signing and verification of JWT tokens.
    | For HMAC algorithms (HS256, HS384, HS512) use secret_key.
    | For RSA/ECDSA algorithms use private_key and public_key.
    |
    */
    'keys' => [
        'secret_key' => env('JWT_SECRET'),
        'private_key' => null, // path to private key file or key content
        'public_key' => null,  // path to public key file or key content
        'passphrase' => null,  // passphrase for private key (if any)
    ],

    /*
    |--------------------------------------------------------------------------
    | Access Token Settings
    |--------------------------------------------------------------------------
    |
    | Configuration for access tokens including time-to-live (TTL).
    | TTL is specified in seconds.
    |
    */
    'access_token' => [
        'ttl' => 900, // 15 minutes
    ],

    /*
    |--------------------------------------------------------------------------
    | Refresh Token Settings
    |--------------------------------------------------------------------------
    |
    | Configuration for refresh tokens including TTL and rotation.
    | Rotation creates a new refresh token on each refresh operation.
    |
    */
    'refresh_token' => [
        'ttl' => 604800, // 7 days
        'rotation' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Settings
    |--------------------------------------------------------------------------
    |
    | Configuration for caching JWT tokens and related data.
    | Prefix is used for cache keys to avoid conflicts.
    |
    */
    'cache' => [
        'prefix' => 'jwt_auth:',
        'ttl' => null, // null = use token TTL
    ],

    /*
    |--------------------------------------------------------------------------
    | Token Blacklist
    |--------------------------------------------------------------------------
    |
    | Configuration for token blacklisting to revoke tokens before expiration.
    | Grace period allows tokens to be valid for a short time after blacklisting.
    |
    */
    'blacklist' => [
        'enabled' => true,
        'grace_period' => 0, // seconds
    ],

    /*
    |--------------------------------------------------------------------------
    | Single Sign-On Mode
    |--------------------------------------------------------------------------
    |
    | When enabled, only one active session per user is allowed.
    | New logins will invalidate previous sessions.
    |
    */
    'sso_mode' => false,

    /*
    |--------------------------------------------------------------------------
    | Token Issuer
    |--------------------------------------------------------------------------
    |
    | The issuer (iss) claim identifies the principal that issued the JWT.
    | This should be a unique identifier for your application or service.
    |
    */
    'issuer' => 'jwt-auth',
];
