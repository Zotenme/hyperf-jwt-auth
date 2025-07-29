# Usage Examples

## Basic Authentication Flow

### 1. User Login

```php
<?php

use Zotenme\JwtAuth\Contract\JwtManagerInterface;
use Zotenme\JwtAuth\Exception\JwtException;

class AuthController
{
    public function __construct(
        private JwtManagerInterface $jwtManager
    ) {}

    public function login(LoginRequest $request): JsonResponse
    {
        // Validate user credentials
        $user = $this->authenticateUser($request->email, $request->password);
        
        if (!$user) {
            return new JsonResponse(['error' => 'Invalid credentials'], 401);
        }

        // Generate token pair
        $tokenPair = $this->jwtManager->generateTokenPair(
            subjectId: (string) $user->id,
            payload: [
                'email' => $user->email,
                'role' => $user->role,
                'permissions' => $user->permissions,
                'organization_id' => $user->organization_id,
            ]
        );

        return new JsonResponse([
            'access_token' => $tokenPair->accessToken,
            'refresh_token' => $tokenPair->refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => $tokenPair->accessExpiresIn,
        ]);
    }
}
```

### 2. Token Validation

```php
<?php

use Zotenme\JwtAuth\Exception\TokenExpiredException;
use Zotenme\JwtAuth\Exception\TokenInvalidException;
use Zotenme\JwtAuth\Exception\TokenBlacklistedException;

class UserController
{
    public function getProfile(string $token): JsonResponse
    {
        try {
            $payload = $this->jwtManager->validateAccessToken($token);
            
            return new JsonResponse([
                'user_id' => $payload->subject,
                'email' => $payload->getClaim('email'),
                'role' => $payload->getClaim('role'),
                'permissions' => $payload->getClaim('permissions'),
                'expires_at' => date('Y-m-d H:i:s', $payload->expiresAt),
            ]);
        } catch (TokenExpiredException $e) {
            return new JsonResponse(['error' => 'Token expired'], 401);
        } catch (TokenBlacklistedException $e) {
            return new JsonResponse(['error' => 'Token revoked'], 401);
        } catch (TokenInvalidException $e) {
            return new JsonResponse(['error' => 'Invalid token'], 401);
        }
    }
}
```

### 3. Token Refresh

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
            'token_type' => 'Bearer',
            'expires_in' => $tokenPair->accessExpiresIn,
        ]);
    } catch (TokenExpiredException $e) {
        return new JsonResponse(['error' => 'Refresh token expired'], 401);
    } catch (TokenInvalidException $e) {
        return new JsonResponse(['error' => 'Invalid refresh token'], 401);
    }
}
```

### 4. User Logout

```php
<?php

public function logout(LogoutRequest $request): JsonResponse
{
    try {
        $token = $request->input('token'); // Can be access or refresh token
        
        // Add token to blacklist
        $this->jwtManager->revokeToken($token);

        return new JsonResponse(['message' => 'Successfully logged out']);
    } catch (JwtException $e) {
        return new JsonResponse(['error' => 'Logout failed'], 400);
    }
}
```

## Advanced Usage Patterns

### Working with Custom Claims

```php
<?php

// Generate token with rich payload
$tokenPair = $this->jwtManager->generateTokenPair(
    subjectId: 'user-123',
    payload: [
        'role' => 'admin',
        'permissions' => ['users:read', 'users:write', 'admin:all'],
        'organization' => [
            'id' => 'org-456',
            'name' => 'Acme Corp',
            'tier' => 'enterprise'
        ],
        'metadata' => [
            'last_login' => time(),
            'ip_address' => $request->getClientIp(),
            'user_agent' => $request->getHeaderLine('User-Agent'),
        ]
    ]
);

// Extract claims from token
$payload = $this->jwtManager->validateAccessToken($token);

$userId = $payload->subject;
$userRole = $payload->getClaim('role');
$permissions = $payload->getClaim('permissions', []);
$organization = $payload->getClaim('organization');
$lastLogin = $payload->getClaim('metadata.last_login', 0);
```

### Role-Based Access Control

```php
<?php

class RoleMiddleware
{
    public function __construct(
        private JwtManagerInterface $jwtManager
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->extractToken($request);
        $payload = $this->jwtManager->validateAccessToken($token);
        
        $userRole = $payload->getClaim('role');
        $requiredRole = $request->getAttribute('required_role');
        
        if (!$this->hasRequiredRole($userRole, $requiredRole)) {
            throw new ForbiddenException('Insufficient permissions');
        }
        
        return $handler->handle($request->withAttribute('user_payload', $payload));
    }
    
    private function hasRequiredRole(string $userRole, string $requiredRole): bool
    {
        $roleHierarchy = [
            'user' => 1,
            'moderator' => 2,
            'admin' => 3,
            'super_admin' => 4
        ];
        
        return ($roleHierarchy[$userRole] ?? 0) >= ($roleHierarchy[$requiredRole] ?? 999);
    }
}
```

### Multi-Tenant Applications

```php
<?php

// Generate tenant-specific tokens
$tokenPair = $this->jwtManager->generateTokenPair(
    subjectId: $user->id,
    payload: [
        'tenant_id' => $user->tenant_id,
        'tenant_role' => $user->getTenantRole(),
        'allowed_tenants' => $user->getAllowedTenants(),
    ]
);

// Validate tenant access
public function validateTenantAccess(string $token, string $requiredTenantId): bool
{
    $payload = $this->jwtManager->validateAccessToken($token);
    
    $userTenantId = $payload->getClaim('tenant_id');
    $allowedTenants = $payload->getClaim('allowed_tenants', []);
    
    return $userTenantId === $requiredTenantId || 
           in_array($requiredTenantId, $allowedTenants);
}
```

### API Key Authentication

```php
<?php

// Generate long-lived API tokens
$apiToken = $this->jwtManager->generateTokenPair(
    subjectId: 'api-key-' . $apiKey->id,
    payload: [
        'api_key_id' => $apiKey->id,
        'api_key_name' => $apiKey->name,
        'scopes' => $apiKey->scopes,
        'rate_limit' => $apiKey->rate_limit,
        'is_api_token' => true,
    ]
);

// Different TTL for API tokens
// Configure in jwt.php:
'access_token' => [
    'ttl' => env('API_TOKEN_TTL', 31536000), // 1 year for API tokens
],
```

### Token Introspection

```php
<?php

public function introspect(IntrospectRequest $request): JsonResponse
{
    try {
        $token = $request->input('token');
        $payload = $this->jwtManager->validateAccessToken($token);
        
        return new JsonResponse([
            'active' => true,
            'sub' => $payload->subject,
            'iat' => $payload->issuedAt,
            'exp' => $payload->expiresAt,
            'jti' => $payload->jwtId,
            'custom_claims' => $payload->customClaims,
        ]);
    } catch (JwtException $e) {
        return new JsonResponse(['active' => false]);
    }
}
```

### Batch Token Operations

```php
<?php

// Revoke all user tokens (useful for security incidents)
public function revokeAllUserTokens(string $userId): void
{
    // This is handled automatically when SSO mode is enabled
    // For manual implementation:
    $userTokens = $this->tokenStorage->getUserActiveTokens($userId);
    
    foreach ($userTokens as $tokenJti) {
        $this->tokenStorage->revokeToken($tokenJti);
    }
    
    $this->tokenStorage->clearUserTokens($userId);
}

// Generate multiple tokens for different purposes
public function generateMultipleTokens(User $user): array
{
    return [
        'web' => $this->jwtManager->generateTokenPair(
            $user->id,
            ['scope' => 'web', 'device' => 'browser']
        ),
        'mobile' => $this->jwtManager->generateTokenPair(
            $user->id,
            ['scope' => 'mobile', 'device' => 'app']
        ),
        'api' => $this->jwtManager->generateTokenPair(
            $user->id,
            ['scope' => 'api', 'device' => 'server']
        ),
    ];
}
```
