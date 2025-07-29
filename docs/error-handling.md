# Error Handling Guide

## Exception Types

The JWT Auth package provides specific exceptions for different error scenarios:

### Base Exception

```php
Zotenme\JwtAuth\Exception\JwtException
```
- Base class for all JWT-related exceptions
- Use for general JWT operation failures

### Specific Exceptions

#### TokenExpiredException
```php
Zotenme\JwtAuth\Exception\TokenExpiredException
```
- Thrown when token has expired
- Default HTTP status: 401
- Default message: "Token has expired"

#### TokenInvalidException
```php
Zotenme\JwtAuth\Exception\TokenInvalidException
```
- Thrown when token is malformed or invalid
- Default HTTP status: 401
- Default message: "Token is invalid"

#### TokenBlacklistedException
```php
Zotenme\JwtAuth\Exception\TokenBlacklistedException
```
- Thrown when token has been revoked
- Default HTTP status: 401
- Default message: "Token is blacklisted"

## Exception Handling Patterns

### Basic Error Handling

```php
<?php

use Zotenme\JwtAuth\Exception\TokenExpiredException;
use Zotenme\JwtAuth\Exception\TokenInvalidException;
use Zotenme\JwtAuth\Exception\TokenBlacklistedException;
use Zotenme\JwtAuth\Exception\JwtException;

class AuthController
{
    public function validateToken(ValidateTokenRequest $request): JsonResponse
    {
        try {
            $token = $request->input('token');
            $payload = $this->jwtManager->validateAccessToken($token);
            
            return new JsonResponse([
                'valid' => true,
                'user_id' => $payload->subject,
                'expires_at' => date('Y-m-d H:i:s', $payload->expiresAt),
            ]);
        } catch (TokenExpiredException $e) {
            return new JsonResponse([
                'valid' => false,
                'error' => 'token_expired',
                'message' => 'Your session has expired. Please log in again.',
            ], 401);
        } catch (TokenBlacklistedException $e) {
            return new JsonResponse([
                'valid' => false,
                'error' => 'token_revoked',
                'message' => 'This token has been revoked.',
            ], 401);
        } catch (TokenInvalidException $e) {
            return new JsonResponse([
                'valid' => false,
                'error' => 'token_invalid',
                'message' => 'The provided token is invalid.',
            ], 401);
        } catch (JwtException $e) {
            return new JsonResponse([
                'valid' => false,
                'error' => 'jwt_error',
                'message' => 'Authentication error occurred.',
            ], 401);
        }
    }
}
```

### Centralized Exception Handler

```php
<?php

namespace App\Exception\Handler;

use Hyperf\ExceptionHandler\ExceptionHandler;
use Hyperf\HttpMessage\Stream\SwooleStream;
use Psr\Http\Message\ResponseInterface;
use Throwable;
use Zotenme\JwtAuth\Exception\JwtException;
use Zotenme\JwtAuth\Exception\TokenExpiredException;
use Zotenme\JwtAuth\Exception\TokenInvalidException;
use Zotenme\JwtAuth\Exception\TokenBlacklistedException;

class JwtExceptionHandler extends ExceptionHandler
{
    public function handle(Throwable $throwable, ResponseInterface $response): ResponseInterface
    {
        if (!$this->isValid($throwable)) {
            return $response;
        }

        $error = $this->formatError($throwable);
        
        $response = $response
            ->withStatus($error['status'])
            ->withHeader('Content-Type', 'application/json')
            ->withBody(new SwooleStream(json_encode($error['body'])));

        // Log the error for debugging
        $this->logger->warning('JWT Authentication Error', [
            'exception' => get_class($throwable),
            'message' => $throwable->getMessage(),
            'file' => $throwable->getFile(),
            'line' => $throwable->getLine(),
        ]);

        return $response;
    }

    public function isValid(Throwable $throwable): bool
    {
        return $throwable instanceof JwtException;
    }

    private function formatError(Throwable $throwable): array
    {
        switch (get_class($throwable)) {
            case TokenExpiredException::class:
                return [
                    'status' => 401,
                    'body' => [
                        'error' => 'token_expired',
                        'message' => 'Your session has expired. Please log in again.',
                        'code' => 'JWT_TOKEN_EXPIRED',
                    ],
                ];

            case TokenBlacklistedException::class:
                return [
                    'status' => 401,
                    'body' => [
                        'error' => 'token_revoked',
                        'message' => 'This token has been revoked.',
                        'code' => 'JWT_TOKEN_REVOKED',
                    ],
                ];

            case TokenInvalidException::class:
                return [
                    'status' => 401,
                    'body' => [
                        'error' => 'token_invalid',
                        'message' => 'The provided token is invalid.',
                        'code' => 'JWT_TOKEN_INVALID',
                    ],
                ];

            default:
                return [
                    'status' => 401,
                    'body' => [
                        'error' => 'authentication_failed',
                        'message' => 'Authentication failed.',
                        'code' => 'JWT_AUTH_FAILED',
                    ],
                ];
        }
    }
}
```

### Register Exception Handler

```php
<?php

// config/autoload/exceptions.php
return [
    'handler' => [
        'http' => [
            \App\Exception\Handler\JwtExceptionHandler::class,
            \Hyperf\HttpServer\Exception\Handler\HttpExceptionHandler::class,
        ],
    ],
];
```

## Advanced Error Handling

### Custom Error Responses

```php
<?php

class JwtErrorResponseFactory
{
    public static function createExpiredTokenResponse(): JsonResponse
    {
        return new JsonResponse([
            'error' => [
                'type' => 'authentication_error',
                'code' => 'TOKEN_EXPIRED',
                'message' => 'Your session has expired',
                'details' => 'Please refresh your token or log in again',
                'timestamp' => time(),
            ],
            'meta' => [
                'refresh_endpoint' => '/auth/refresh',
                'login_endpoint' => '/auth/login',
            ],
        ], 401);
    }

    public static function createInvalidTokenResponse(): JsonResponse
    {
        return new JsonResponse([
            'error' => [
                'type' => 'authentication_error',
                'code' => 'TOKEN_INVALID',
                'message' => 'Invalid authentication token',
                'details' => 'The provided token is malformed or corrupted',
                'timestamp' => time(),
            ],
        ], 401);
    }

    public static function createRevokedTokenResponse(): JsonResponse
    {
        return new JsonResponse([
            'error' => [
                'type' => 'authentication_error',
                'code' => 'TOKEN_REVOKED',
                'message' => 'Token has been revoked',
                'details' => 'This token is no longer valid',
                'timestamp' => time(),
            ],
        ], 401);
    }
}
```

### Error Context Enrichment

```php
<?php

class EnrichedJwtExceptionHandler extends ExceptionHandler
{
    public function handle(Throwable $throwable, ResponseInterface $response): ResponseInterface
    {
        if (!$this->isValid($throwable)) {
            return $response;
        }

        $context = $this->gatherContext();
        $error = $this->formatErrorWithContext($throwable, $context);
        
        return $response
            ->withStatus($error['status'])
            ->withHeader('Content-Type', 'application/json')
            ->withBody(new SwooleStream(json_encode($error['body'])));
    }

    private function gatherContext(): array
    {
        $request = Context::get(ServerRequestInterface::class);
        
        return [
            'request_id' => $request?->getHeaderLine('X-Request-ID') ?? uniqid(),
            'timestamp' => time(),
            'ip_address' => $request?->getServerParams()['remote_addr'] ?? 'unknown',
            'user_agent' => $request?->getHeaderLine('User-Agent') ?? 'unknown',
            'endpoint' => $request?->getUri()->getPath() ?? 'unknown',
        ];
    }

    private function formatErrorWithContext(Throwable $throwable, array $context): array
    {
        $baseError = $this->formatError($throwable);
        
        $baseError['body']['context'] = $context;
        $baseError['body']['support'] = [
            'contact' => 'support@example.com',
            'documentation' => 'https://docs.example.com/auth-errors',
        ];

        return $baseError;
    }
}
```

## Client-Side Error Handling

### JavaScript/TypeScript Example

```typescript
interface AuthError {
    error: string;
    message: string;
    code: string;
    timestamp: number;
}

class AuthClient {
    private baseUrl: string;
    private accessToken: string | null = null;

    async makeAuthenticatedRequest(url: string, options: RequestInit = {}): Promise<Response> {
        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json',
        };

        try {
            const response = await fetch(`${this.baseUrl}${url}`, {
                ...options,
                headers,
            });

            if (response.status === 401) {
                await this.handleAuthError(response);
                // Retry the original request after token refresh
                return this.makeAuthenticatedRequest(url, options);
            }

            return response;
        } catch (error) {
            console.error('Request failed:', error);
            throw error;
        }
    }

    private async handleAuthError(response: Response): Promise<void> {
        const error: AuthError = await response.json();

        switch (error.code) {
            case 'JWT_TOKEN_EXPIRED':
                await this.refreshToken();
                break;

            case 'JWT_TOKEN_REVOKED':
            case 'JWT_TOKEN_INVALID':
                this.redirectToLogin();
                break;

            default:
                console.error('Unknown auth error:', error);
                this.redirectToLogin();
        }
    }

    private async refreshToken(): Promise<void> {
        try {
            const refreshToken = localStorage.getItem('refresh_token');
            const response = await fetch(`${this.baseUrl}/auth/refresh`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: refreshToken }),
            });

            if (response.ok) {
                const data = await response.json();
                this.accessToken = data.access_token;
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('refresh_token', data.refresh_token);
            } else {
                this.redirectToLogin();
            }
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.redirectToLogin();
        }
    }

    private redirectToLogin(): void {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = '/login';
    }
}
```

## Error Monitoring

### Logging JWT Errors

```php
<?php

class JwtErrorLogger
{
    public function __construct(
        private LoggerInterface $logger
    ) {}

    public function logAuthenticationFailure(
        string $error,
        string $token = null,
        ServerRequestInterface $request = null
    ): void {
        $context = [
            'error_type' => $error,
            'timestamp' => time(),
        ];

        if ($request) {
            $context['request'] = [
                'method' => $request->getMethod(),
                'uri' => (string) $request->getUri(),
                'ip' => $request->getServerParams()['remote_addr'] ?? 'unknown',
                'user_agent' => $request->getHeaderLine('User-Agent'),
            ];
        }

        if ($token) {
            // Log token info without exposing the actual token
            try {
                $parts = explode('.', $token);
                $header = json_decode(base64_decode($parts[0]), true);
                $payload = json_decode(base64_decode($parts[1]), true);
                
                $context['token_info'] = [
                    'algorithm' => $header['alg'] ?? 'unknown',
                    'type' => $header['typ'] ?? 'unknown',
                    'subject' => $payload['sub'] ?? 'unknown',
                    'expires_at' => $payload['exp'] ?? null,
                ];
            } catch (\Exception $e) {
                $context['token_info'] = ['error' => 'Could not parse token'];
            }
        }

        $this->logger->warning('JWT Authentication Failed', $context);
    }
}
```

### Metrics Collection

```php
<?php

class JwtMetricsCollector
{
    private array $errorCounts = [];

    public function recordError(string $errorType): void
    {
        $this->errorCounts[$errorType] = ($this->errorCounts[$errorType] ?? 0) + 1;
    }

    public function getErrorCounts(): array
    {
        return $this->errorCounts;
    }

    public function recordAuthenticationAttempt(bool $successful): void
    {
        $key = $successful ? 'auth_success' : 'auth_failure';
        $this->errorCounts[$key] = ($this->errorCounts[$key] ?? 0) + 1;
    }
}
```

## Testing Error Scenarios

### Unit Tests for Error Handling

```php
<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use Zotenme\JwtAuth\Exception\TokenExpiredException;

class JwtErrorHandlingTest extends TestCase
{
    public function testExpiredTokenThrowsCorrectException(): void
    {
        $jwtManager = $this->createJwtManager();
        $expiredToken = $this->createExpiredToken();

        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired');

        $jwtManager->validateAccessToken($expiredToken);
    }

    public function testInvalidTokenThrowsCorrectException(): void
    {
        $jwtManager = $this->createJwtManager();
        $invalidToken = 'invalid.token.here';

        $this->expectException(TokenInvalidException::class);

        $jwtManager->validateAccessToken($invalidToken);
    }
}
```

## Error Recovery Strategies

### Automatic Token Refresh

```php
<?php

class AutoRefreshTokenManager
{
    public function __construct(
        private JwtManagerInterface $jwtManager,
        private TokenStorageInterface $tokenStorage
    ) {}

    public function validateWithAutoRefresh(string $accessToken, string $refreshToken = null): JwtPayload
    {
        try {
            return $this->jwtManager->validateAccessToken($accessToken);
        } catch (TokenExpiredException $e) {
            if ($refreshToken) {
                $tokenPair = $this->jwtManager->refreshAccessToken($refreshToken);
                return $this->jwtManager->validateAccessToken($tokenPair->accessToken);
            }
            throw $e;
        }
    }
}
```

### Graceful Degradation

```php
<?php

class GracefulAuthService
{
    public function getAuthenticatedUser(string $token): ?User
    {
        try {
            $payload = $this->jwtManager->validateAccessToken($token);
            return $this->userRepository->find($payload->subject);
        } catch (JwtException $e) {
            // Log the error but don't throw - return null for anonymous access
            $this->logger->info('Authentication failed, proceeding as anonymous user', [
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }
}
```
