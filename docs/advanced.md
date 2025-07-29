# Advanced Features

## Token Rotation

Token rotation automatically generates new refresh tokens when refreshing access tokens, providing enhanced security.

### Configuration

```php
// config/autoload/jwt.php
'refresh_token' => [
    'ttl' => 604800, // 7 days
    'rotation_enabled' => true, // Enable rotation
],
```

### How It Works

1. User provides refresh token
2. System validates refresh token
3. Old refresh token is revoked (blacklisted)
4. New token pair is generated
5. Both tokens are returned

### Implementation

```php
public function refreshWithRotation(string $refreshToken): TokenPair
{
    // Validate current refresh token
    $payload = $this->jwtManager->validateRefreshToken($refreshToken);
    
    // Generate new token pair (old refresh token is automatically revoked)
    $newTokenPair = $this->jwtManager->refreshAccessToken($refreshToken);
    
    return $newTokenPair;
}
```

### Benefits

- **Theft Detection**: If stolen token is used, legitimate user will get error on next refresh
- **Limited Exposure**: Old tokens become invalid immediately
- **Automatic Cleanup**: No accumulation of old refresh tokens

## Single Sign-On (SSO) Mode

SSO mode ensures only one active session per user by revoking all existing tokens when generating new ones.

### Configuration

```php
// config/autoload/jwt.php
'sso_mode' => true,
```

### Implementation Example

```php
class AuthController
{
    public function login(LoginRequest $request): JsonResponse
    {
        $user = $this->authenticateUser($request);
        
        // When SSO is enabled, this will revoke all existing user tokens
        $tokenPair = $this->jwtManager->generateTokenPair(
            subjectId: (string) $user->id,
            payload: ['role' => $user->role]
        );
        
        return new JsonResponse([
            'access_token' => $tokenPair->accessToken,
            'refresh_token' => $tokenPair->refreshToken,
            'message' => 'Previous sessions have been terminated'
        ]);
    }
}
```

### Manual SSO Implementation

```php
public function loginWithCustomSSO(string $userId): TokenPair
{
    // Manually revoke all user tokens before generating new ones
    $this->tokenStorage->revokeAllUserTokens($userId);
    
    // Generate new token pair
    return $this->jwtManager->generateTokenPair($userId);
}
```

## RSA/ECDSA Algorithms

For distributed systems where public key verification is needed.

### RSA Configuration

```php
// config/autoload/jwt.php
'algorithm' => 'RS256',
'keys' => [
    'private_key' => '/path/to/rsa-private.pem',
    'public_key' => '/path/to/rsa-public.pem',
    'passphrase' => env('RSA_PASSPHRASE'), // Optional
],
```

### ECDSA Configuration

```php
// config/autoload/jwt.php
'algorithm' => 'ES256',
'keys' => [
    'private_key' => '/path/to/ecdsa-private.pem',
    'public_key' => '/path/to/ecdsa-public.pem',
],
```

### Key Generation

#### RSA Keys

```bash
# Generate 2048-bit RSA private key
openssl genrsa -out rsa-private.pem 2048

# Generate 4096-bit RSA private key (more secure)
openssl genrsa -out rsa-private.pem 4096

# Extract public key
openssl rsa -in rsa-private.pem -pubout -out rsa-public.pem

# Generate with passphrase
openssl genrsa -aes256 -out rsa-private-encrypted.pem 2048
```

#### ECDSA Keys

```bash
# P-256 curve (for ES256)
openssl ecparam -genkey -name secp256r1 -noout -out ecdsa-private.pem
openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem

# P-384 curve (for ES384)
openssl ecparam -genkey -name secp384r1 -noout -out ecdsa-private.pem

# P-521 curve (for ES512)
openssl ecparam -genkey -name secp521r1 -noout -out ecdsa-private.pem
```

### Distributed Verification

```php
// Service A (Token Generator)
class TokenGeneratorService
{
    public function __construct(
        private JwtManagerInterface $jwtManager // Uses private key
    ) {}
    
    public function issueToken(string $userId): string
    {
        $tokenPair = $this->jwtManager->generateTokenPair($userId);
        return $tokenPair->accessToken;
    }
}

// Service B (Token Validator)
class TokenValidatorService
{
    public function __construct(
        private JwtManagerInterface $jwtManager // Uses public key
    ) {}
    
    public function validateToken(string $token): JwtPayload
    {
        return $this->jwtManager->validateAccessToken($token);
    }
}
```

## Custom Token Storage

Implement custom storage backends for specific requirements.

### Redis Implementation

```php
use Zotenme\JwtAuth\Contract\TokenStorageInterface;

class RedisTokenStorage implements TokenStorageInterface
{
    public function __construct(
        private \Redis $redis,
        private JwtConfig $config
    ) {}
    
    public function revokeToken(string $jti, ?int $ttl = null): void
    {
        if (!$this->isBlacklistEnabled()) {
            return;
        }
        
        $key = $this->config->getCachePrefix() . 'blacklist:' . $jti;
        $this->redis->setex($key, $ttl ?? $this->config->getAccessTokenTtl(), 1);
    }
    
    public function isTokenRevoked(string $jti): bool
    {
        if (!$this->isBlacklistEnabled()) {
            return false;
        }
        
        $key = $this->config->getCachePrefix() . 'blacklist:' . $jti;
        return (bool) $this->redis->exists($key);
    }
    
    // ... implement other methods
}
```

### Database Implementation

```php
class DatabaseTokenStorage implements TokenStorageInterface
{
    public function __construct(
        private ConnectionInterface $db,
        private JwtConfig $config
    ) {}
    
    public function revokeToken(string $jti, ?int $ttl = null): void
    {
        if (!$this->isBlacklistEnabled()) {
            return;
        }
        
        $expiresAt = time() + ($ttl ?? $this->config->getAccessTokenTtl());
        
        $this->db->table('jwt_blacklist')->insert([
            'jti' => $jti,
            'expires_at' => date('Y-m-d H:i:s', $expiresAt),
            'created_at' => date('Y-m-d H:i:s'),
        ]);
    }
    
    public function isTokenRevoked(string $jti): bool
    {
        if (!$this->isBlacklistEnabled()) {
            return false;
        }
        
        return $this->db->table('jwt_blacklist')
            ->where('jti', $jti)
            ->where('expires_at', '>', date('Y-m-d H:i:s'))
            ->exists();
    }
}
```

## Custom JWT Claims

### Adding Custom Claims

```php
public function generateEnrichedToken(User $user): TokenPair
{
    return $this->jwtManager->generateTokenPair(
        subjectId: (string) $user->id,
        payload: [
            // Standard claims
            'email' => $user->email,
            'role' => $user->role,
            
            // Organization claims
            'org_id' => $user->organization_id,
            'org_role' => $user->organization_role,
            
            // Permission claims
            'permissions' => $user->getPermissions(),
            'scopes' => $user->getScopes(),
            
            // Metadata claims
            'metadata' => [
                'last_login' => $user->last_login?->getTimestamp(),
                'login_count' => $user->login_count,
                'mfa_enabled' => $user->mfa_enabled,
            ],
            
            // Session claims
            'session_id' => Uuid::uuid4()->toString(),
            'device_type' => $this->detectDeviceType(),
            'ip_address' => $this->request->getClientIp(),
        ]
    );
}
```

### Nested Claims Access

```php
public function getNestedClaim(JwtPayload $payload, string $path, mixed $default = null): mixed
{
    $keys = explode('.', $path);
    $value = $payload->customClaims;
    
    foreach ($keys as $key) {
        if (!is_array($value) || !isset($value[$key])) {
            return $default;
        }
        $value = $value[$key];
    }
    
    return $value;
}

// Usage
$lastLogin = $this->getNestedClaim($payload, 'metadata.last_login', 0);
$orgRole = $this->getNestedClaim($payload, 'org_role', 'member');
```

## Token Scoping

Implement fine-grained access control with scopes.

### Scope-Based Tokens

```php
class ScopedTokenGenerator
{
    public function generateApiToken(User $user, array $scopes): TokenPair
    {
        return $this->jwtManager->generateTokenPair(
            subjectId: (string) $user->id,
            payload: [
                'token_type' => 'api',
                'scopes' => $scopes,
                'rate_limit' => $user->getRateLimit(),
                'created_at' => time(),
            ]
        );
    }
    
    public function generateWebToken(User $user): TokenPair
    {
        return $this->jwtManager->generateTokenPair(
            subjectId: (string) $user->id,
            payload: [
                'token_type' => 'web',
                'scopes' => ['web:full'],
                'session_id' => session_id(),
            ]
        );
    }
}
```

### Scope Validation

```php
class ScopeValidator
{
    public function validateScope(JwtPayload $payload, string $requiredScope): bool
    {
        $tokenScopes = $payload->getClaim('scopes', []);
        
        // Check exact match
        if (in_array($requiredScope, $tokenScopes)) {
            return true;
        }
        
        // Check wildcard scopes
        foreach ($tokenScopes as $scope) {
            if ($this->matchesWildcard($scope, $requiredScope)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function matchesWildcard(string $scope, string $required): bool
    {
        if (str_ends_with($scope, '*')) {
            $prefix = substr($scope, 0, -1);
            return str_starts_with($required, $prefix);
        }
        
        return false;
    }
}

// Usage
$hasReadAccess = $scopeValidator->validateScope($payload, 'users:read');
$hasAdminAccess = $scopeValidator->validateScope($payload, 'admin:*');
```
