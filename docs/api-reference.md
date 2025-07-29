# API Reference

## JwtManagerInterface

The main interface for JWT operations.

### Methods

#### `generateTokenPair(string $subjectId, array $payload = []): TokenPair`

Generates a new access and refresh token pair.

**Parameters:**
- `$subjectId` (string) - Unique identifier for the token subject (usually user ID)
- `$payload` (array) - Additional claims to include in the token

**Returns:** `TokenPair` object containing both tokens and their TTL

**Throws:**
- `JwtException` - If subject ID is empty or token generation fails

**Example:**
```php
$tokenPair = $jwtManager->generateTokenPair(
    'user-123',
    ['role' => 'admin', 'permissions' => ['read', 'write']]
);
```

#### `refreshAccessToken(string $refreshToken): TokenPair`

Creates a new access token using a refresh token.

**Parameters:**
- `$refreshToken` (string) - Valid refresh token

**Returns:** `TokenPair` object with new access token

**Throws:**
- `TokenExpiredException` - If refresh token has expired
- `TokenInvalidException` - If refresh token is malformed
- `TokenBlacklistedException` - If refresh token is revoked

#### `validateAccessToken(string $accessToken): JwtPayload`

Validates and parses an access token.

**Parameters:**
- `$accessToken` (string) - Token to validate

**Returns:** `JwtPayload` object with token data

**Throws:**
- `TokenExpiredException` - If token has expired
- `TokenInvalidException` - If token is malformed
- `TokenBlacklistedException` - If token is revoked

#### `validateRefreshToken(string $refreshToken): JwtPayload`

Validates and parses a refresh token.

**Parameters:**
- `$refreshToken` (string) - Token to validate

**Returns:** `JwtPayload` object with token data

**Throws:**
- Same exceptions as `validateAccessToken()`

#### `revokeToken(string $token): void`

Revokes a token by adding it to the blacklist.

**Parameters:**
- `$token` (string) - Token to revoke (access or refresh)

**Throws:**
- `TokenInvalidException` - If token cannot be parsed
- `JwtException` - If revocation fails

## JwtPayload

Represents the parsed content of a JWT token.

### Properties

- `string $subject` - Token subject (usually user ID)
- `int $issuedAt` - Token creation timestamp
- `int $expiresAt` - Token expiration timestamp  
- `string $jwtId` - Unique token identifier
- `array $customClaims` - Additional custom claims

### Methods

#### `isExpired(): bool`

Checks if the token has expired.

**Returns:** `true` if token is expired, `false` otherwise

#### `getClaim(string $key, mixed $default = null): mixed`

Retrieves a claim value.

**Parameters:**
- `$key` (string) - Claim name
- `$default` (mixed) - Default value if claim doesn't exist

**Returns:** Claim value or default

**Example:**
```php
$role = $payload->getClaim('role', 'guest');
$permissions = $payload->getClaim('permissions', []);
```

## TokenPair

Represents a pair of access and refresh tokens.

### Properties

- `string $accessToken` - The access token
- `string $refreshToken` - The refresh token
- `int $accessExpiresIn` - Access token TTL in seconds
- `int $refreshExpiresIn` - Refresh token TTL in seconds

### Methods

#### `toArray(): array`

Converts the token pair to an array.

**Returns:** Array with token data

**Example:**
```php
$data = $tokenPair->toArray();
// Returns:
// [
//     'access_token' => '...',
//     'refresh_token' => '...',
//     'access_expires_in' => 900,
//     'refresh_expires_in' => 604800
// ]
```

## TokenStorageInterface

Interface for token storage operations (caching, blacklisting).

### Methods

#### `set(string $key, mixed $value, ?int $ttl = null): bool`

Stores a value in cache.

#### `get(string $key, mixed $default = null): mixed`

Retrieves a value from cache.

#### `delete(string $key): bool`

Deletes a value from cache.

#### `exists(string $key): bool`

Checks if a key exists in cache.

#### `revokeToken(string $jti, ?int $ttl = null): void`

Adds a token to the blacklist.

#### `isTokenRevoked(string $jti): bool`

Checks if a token is blacklisted.

#### `revokeAllUserTokens(string $subjectId): void`

Revokes all tokens for a specific user.

#### `registerUserToken(string $subjectId, string $jti, bool $ssoMode = false): void`

Registers a new token for a user.

#### `unregisterUserToken(string $subjectId, string $jti): void`

Removes a token from user's active tokens.

#### `getUserActiveTokens(string $subjectId): array`

Gets all active tokens for a user.

#### `isBlacklistEnabled(): bool`

Checks if blacklisting is enabled.

#### `isSsoModeEnabled(): bool`

Checks if SSO mode is enabled.

## JwtConfig

Configuration helper class.

### Methods

#### `getAlgorithm(): JwtAlgorithm`

Gets the configured algorithm.

#### `getSecretKey(): string`

Gets the HMAC secret key.

#### `getPrivateKey(): string`

Gets the RSA/ECDSA private key.

#### `getPublicKey(): string`

Gets the RSA/ECDSA public key.

#### `getAccessTokenTtl(): int`

Gets access token TTL in seconds.

#### `getRefreshTokenTtl(): int`

Gets refresh token TTL in seconds.

#### `isRefreshTokenRotationEnabled(): bool`

Checks if token rotation is enabled.

#### `isBlacklistEnabled(): bool`

Checks if blacklisting is enabled.

#### `isSsoModeEnabled(): bool`

Checks if SSO mode is enabled.

## JwtAlgorithm

Enum for supported JWT algorithms.

### Cases

- `HS256` - HMAC using SHA-256
- `HS384` - HMAC using SHA-384  
- `HS512` - HMAC using SHA-512
- `RS256` - RSA using SHA-256
- `RS384` - RSA using SHA-384
- `RS512` - RSA using SHA-512
- `ES256` - ECDSA using P-256 and SHA-256
- `ES384` - ECDSA using P-384 and SHA-384
- `ES512` - ECDSA using P-521 and SHA-512

### Methods

#### `isSymmetric(): bool`

Checks if algorithm is symmetric (HMAC).

#### `isAsymmetric(): bool`

Checks if algorithm is asymmetric (RSA/ECDSA).

#### `static getSupported(): array`

Gets array of all supported algorithm names.

## Exceptions

### JwtException

Base exception for all JWT operations.

### TokenExpiredException

Thrown when a token has expired.

**Default message:** "Token has expired"
**Default code:** 401

### TokenInvalidException

Thrown when a token is malformed or invalid.

**Default message:** "Token is invalid"
**Default code:** 401

### TokenBlacklistedException

Thrown when a token has been revoked.

**Default message:** "Token is blacklisted"
**Default code:** 401

## Response Examples

### Successful Login Response

```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "Bearer",
    "expires_in": 900
}
```

### Token Validation Response

```json
{
    "user_id": "123",
    "email": "user@example.com",
    "role": "admin",
    "permissions": ["read", "write"],
    "expires_at": "2025-07-29 15:30:00"
}
```

### Error Responses

```json
{
    "error": "Token expired"
}
```

```json
{
    "error": "Invalid token"
}
```

```json
{
    "error": "Token revoked"
}
```
