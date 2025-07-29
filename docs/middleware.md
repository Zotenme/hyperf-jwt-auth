# Middleware Integration

## JWT Authentication Middleware

### Basic Implementation

```php
<?php

declare(strict_types=1);

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zotenme\JwtAuth\Contract\JwtManagerInterface;
use Zotenme\JwtAuth\Exception\JwtException;

class JwtAuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private JwtManagerInterface $jwtManager
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->extractToken($request);

        if ($token === null) {
            return $this->unauthorizedResponse('Missing authorization token');
        }

        try {
            $payload = $this->jwtManager->validateAccessToken($token);
            
            // Add JWT data to request attributes
            $request = $request
                ->withAttribute('jwt_payload', $payload)
                ->withAttribute('user_id', $payload->subject)
                ->withAttribute('jwt_claims', $payload->customClaims);

            return $handler->handle($request);
        } catch (JwtException $e) {
            return $this->unauthorizedResponse($e->getMessage());
        }
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        // Check Authorization header
        $authHeader = $request->getHeaderLine('Authorization');
        if (str_starts_with($authHeader, 'Bearer ')) {
            return substr($authHeader, 7);
        }

        // Check query parameter (less secure, use with caution)
        $queryParams = $request->getQueryParams();
        if (isset($queryParams['token'])) {
            return $queryParams['token'];
        }

        return null;
    }

    private function unauthorizedResponse(string $message): ResponseInterface
    {
        return new JsonResponse(['error' => $message], 401);
    }
}
```

### Advanced Middleware with Role-Based Access

```php
<?php

namespace App\Middleware;

class JwtRoleMiddleware implements MiddlewareInterface
{
    public function __construct(
        private JwtManagerInterface $jwtManager,
        private array $requiredRoles = []
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->extractToken($request);
        
        if ($token === null) {
            throw new UnauthorizedException('Missing authorization token');
        }

        try {
            $payload = $this->jwtManager->validateAccessToken($token);
            
            // Check role permissions
            if (!$this->hasRequiredRole($payload)) {
                throw new ForbiddenException('Insufficient permissions');
            }

            $request = $request
                ->withAttribute('jwt_payload', $payload)
                ->withAttribute('user_id', $payload->subject)
                ->withAttribute('user_role', $payload->getClaim('role'))
                ->withAttribute('user_permissions', $payload->getClaim('permissions', []));

            return $handler->handle($request);
        } catch (JwtException $e) {
            throw new UnauthorizedException($e->getMessage());
        }
    }

    private function hasRequiredRole(JwtPayload $payload): bool
    {
        if (empty($this->requiredRoles)) {
            return true; // No role requirements
        }

        $userRole = $payload->getClaim('role');
        $userPermissions = $payload->getClaim('permissions', []);

        // Check direct role match
        if (in_array($userRole, $this->requiredRoles)) {
            return true;
        }

        // Check permission-based access
        foreach ($this->requiredRoles as $role) {
            if (in_array("role:{$role}", $userPermissions)) {
                return true;
            }
        }

        return false;
    }
}
```

### Scope-Based Middleware

```php
<?php

namespace App\Middleware;

class JwtScopeMiddleware implements MiddlewareInterface
{
    public function __construct(
        private JwtManagerInterface $jwtManager,
        private array $requiredScopes = []
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->extractToken($request);
        $payload = $this->jwtManager->validateAccessToken($token);

        if (!$this->hasRequiredScopes($payload)) {
            throw new ForbiddenException('Insufficient scope permissions');
        }

        return $handler->handle($request->withAttribute('jwt_payload', $payload));
    }

    private function hasRequiredScopes(JwtPayload $payload): bool
    {
        $tokenScopes = $payload->getClaim('scopes', []);

        foreach ($this->requiredScopes as $requiredScope) {
            if (!$this->hasScope($tokenScopes, $requiredScope)) {
                return false;
            }
        }

        return true;
    }

    private function hasScope(array $tokenScopes, string $requiredScope): bool
    {
        // Exact match
        if (in_array($requiredScope, $tokenScopes)) {
            return true;
        }

        // Wildcard match
        foreach ($tokenScopes as $scope) {
            if (str_ends_with($scope, '*')) {
                $prefix = substr($scope, 0, -1);
                if (str_starts_with($requiredScope, $prefix)) {
                    return true;
                }
            }
        }

        return false;
    }
}
```

## Token Extraction Strategies

### Multiple Token Sources

```php
<?php

namespace App\Service;

class TokenExtractor
{
    public function extractToken(ServerRequestInterface $request): ?string
    {
        // Strategy 1: Authorization header (preferred)
        $token = $this->extractFromHeader($request);
        if ($token !== null) {
            return $token;
        }

        // Strategy 2: Cookie (for web applications)
        $token = $this->extractFromCookie($request);
        if ($token !== null) {
            return $token;
        }

        // Strategy 3: Query parameter (least secure)
        return $this->extractFromQuery($request);
    }

    private function extractFromHeader(ServerRequestInterface $request): ?string
    {
        $authHeader = $request->getHeaderLine('Authorization');
        
        if (str_starts_with($authHeader, 'Bearer ')) {
            $token = substr($authHeader, 7);
            return !empty($token) ? $token : null;
        }

        return null;
    }

    private function extractFromCookie(ServerRequestInterface $request): ?string
    {
        $cookies = $request->getCookieParams();
        return $cookies['access_token'] ?? null;
    }

    private function extractFromQuery(ServerRequestInterface $request): ?string
    {
        $queryParams = $request->getQueryParams();
        return $queryParams['access_token'] ?? null;
    }
}
```

### Secure Cookie Implementation

```php
<?php

class SecureCookieTokenHandler
{
    public function setTokenCookie(ResponseInterface $response, string $token): ResponseInterface
    {
        $cookieValue = sprintf(
            '%s; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=%d',
            urlencode($token),
            900 // 15 minutes
        );

        return $response->withHeader('Set-Cookie', "access_token={$cookieValue}");
    }

    public function clearTokenCookie(ResponseInterface $response): ResponseInterface
    {
        $cookieValue = 'access_token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0';
        return $response->withHeader('Set-Cookie', $cookieValue);
    }
}
```

## Middleware Registration

### Global Middleware

```php
<?php

// config/autoload/middlewares.php
return [
    'http' => [
        // Global middlewares (applied to all routes)
        \App\Middleware\CorsMiddleware::class,
        \App\Middleware\SecurityHeadersMiddleware::class,
    ],
];
```

### Route-Specific Middleware

```php
<?php

// config/routes.php
use Hyperf\HttpServer\Router\Router;

// Public routes (no authentication)
Router::post('/auth/login', [AuthController::class, 'login']);
Router::post('/auth/refresh', [AuthController::class, 'refresh']);

// Protected routes (require authentication)
Router::addGroup('/api', function () {
    Router::get('/profile', [UserController::class, 'profile']);
    Router::post('/logout', [AuthController::class, 'logout']);
}, [
    'middleware' => [\App\Middleware\JwtAuthMiddleware::class],
]);

// Admin routes (require admin role)
Router::addGroup('/admin', function () {
    Router::get('/users', [AdminController::class, 'users']);
    Router::delete('/users/{id}', [AdminController::class, 'deleteUser']);
}, [
    'middleware' => [
        \App\Middleware\JwtAuthMiddleware::class,
        [\App\Middleware\JwtRoleMiddleware::class, ['admin']],
    ],
]);
```

### Conditional Middleware

```php
<?php

class ConditionalJwtMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();
        
        // Skip authentication for certain paths
        $publicPaths = ['/health', '/metrics', '/docs'];
        
        foreach ($publicPaths as $publicPath) {
            if (str_starts_with($path, $publicPath)) {
                return $handler->handle($request);
            }
        }

        // Apply JWT authentication for other paths
        return $this->jwtAuthMiddleware->process($request, $handler);
    }
}
```

## Middleware Configuration

### Middleware Parameters

```php
<?php

// Pass parameters to middleware
Router::addGroup('/api/v1', function () {
    Router::get('/users', [UserController::class, 'index']);
}, [
    'middleware' => [
        [\App\Middleware\JwtScopeMiddleware::class, ['users:read']],
    ],
]);

Router::addGroup('/api/v1', function () {
    Router::post('/users', [UserController::class, 'create']);
    Router::put('/users/{id}', [UserController::class, 'update']);
}, [
    'middleware' => [
        [\App\Middleware\JwtScopeMiddleware::class, ['users:write']],
    ],
]);
```

### Middleware Factory

```php
<?php

namespace App\Middleware;

class JwtMiddlewareFactory
{
    public static function createRoleMiddleware(array $roles): callable
    {
        return function (ServerRequestInterface $request, RequestHandlerInterface $handler) use ($roles) {
            $middleware = new JwtRoleMiddleware(
                container()->get(JwtManagerInterface::class),
                $roles
            );
            
            return $middleware->process($request, $handler);
        };
    }

    public static function createScopeMiddleware(array $scopes): callable
    {
        return function (ServerRequestInterface $request, RequestHandlerInterface $handler) use ($scopes) {
            $middleware = new JwtScopeMiddleware(
                container()->get(JwtManagerInterface::class),
                $scopes
            );
            
            return $middleware->process($request, $handler);
        };
    }
}
```

## Testing Middleware

### Unit Tests

```php
<?php

namespace Tests\Unit\Middleware;

use App\Middleware\JwtAuthMiddleware;
use PHPUnit\Framework\TestCase;

class JwtAuthMiddlewareTest extends TestCase
{
    public function testValidTokenAllowsAccess(): void
    {
        $jwtManager = $this->createMock(JwtManagerInterface::class);
        $payload = new JwtPayload('user-123', time(), time() + 900, 'jwt-id');
        
        $jwtManager->expects($this->once())
            ->method('validateAccessToken')
            ->with('valid-token')
            ->willReturn($payload);

        $middleware = new JwtAuthMiddleware($jwtManager);
        
        $request = $this->createMockRequest('Bearer valid-token');
        $handler = $this->createMockHandler();

        $response = $middleware->process($request, $handler);
        
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testMissingTokenReturnsUnauthorized(): void
    {
        $jwtManager = $this->createMock(JwtManagerInterface::class);
        $middleware = new JwtAuthMiddleware($jwtManager);
        
        $request = $this->createMockRequest(null);
        $handler = $this->createMockHandler();

        $response = $middleware->process($request, $handler);
        
        $this->assertEquals(401, $response->getStatusCode());
    }
}
```
