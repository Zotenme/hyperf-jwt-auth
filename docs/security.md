# Security Guide

## Best Practices

### 1. Secret Key Management

**Never hardcode secrets in your code:**

```php
// ❌ Bad
'secret_key' => 'my-secret-key',

// ✅ Good
'secret_key' => env('JWT_SECRET'),
```

**Generate strong secrets:**

```bash
# Generate a 256-bit random key
openssl rand -base64 32

# Or use PHP
php -r "echo base64_encode(random_bytes(32));"
```

**Store secrets securely:**
- Use environment variables
- Consider using secret management services (AWS Secrets Manager, Azure Key Vault)
- Never commit secrets to version control

### 2. Token Lifetime Configuration

**Access tokens should be short-lived:**

```php
'access_token' => [
    'ttl' => 900, // 15 minutes (recommended)
],
```

**Refresh tokens can be longer:**

```php
'refresh_token' => [
    'ttl' => 604800, // 7 days (reasonable)
],
```

### 3. HTTPS Only

**Always use HTTPS in production:**

- Prevents token interception
- Protects against man-in-the-middle attacks
- Required for secure cookie storage

### 4. Token Storage on Client Side

**Web Applications:**
```javascript
// ❌ Bad - Local Storage (vulnerable to XSS)
localStorage.setItem('token', accessToken);

// ✅ Good - HTTP-only cookies
// Set via server response headers
```

**Mobile Applications:**
- Use secure storage (Keychain on iOS, Keystore on Android)
- Avoid plain text storage

### 5. Enable Token Blacklisting

```php
'blacklist' => [
    'enabled' => true,
    'grace_period' => 0, // No grace period for security
],
```

Benefits:
- Immediate token revocation
- Protection against stolen tokens
- Proper logout functionality

### 6. Token Rotation

```php
'refresh_token' => [
    'rotation_enabled' => true, // Enable for maximum security
],
```

Benefits:
- Limits exposure window
- Detects token theft
- Automatic cleanup of old tokens

### 7. Single Sign-On (SSO) Mode

```php
'sso_mode' => true, // Enable if needed
```

Use when:
- Only one session per user is allowed
- Enhanced security is required
- Compliance requirements

## Algorithm Security

### HMAC Algorithms (HS256, HS384, HS512)

**Pros:**
- Fast performance
- Simple setup
- Good for single-application scenarios

**Cons:**
- Same key for signing and verification
- Not suitable for distributed systems

**Security considerations:**
- Use minimum 256-bit keys
- Protect secret key carefully
- Rotate keys periodically

### RSA Algorithms (RS256, RS384, RS512)

**Pros:**
- Separate keys for signing/verification
- Good for microservices
- Public key can be shared safely

**Security considerations:**
- Use minimum 2048-bit keys (4096-bit recommended)
- Protect private key with passphrase
- Store private key securely

### ECDSA Algorithms (ES256, ES384, ES512)

**Pros:**
- Smaller key sizes than RSA
- Better performance than RSA
- Strong security

**Security considerations:**
- Use appropriate curves (P-256, P-384, P-521)
- Protect private key carefully
- Ensure proper random number generation

## Common Vulnerabilities

### 1. Algorithm Confusion

**Attack:** Change algorithm from RS256 to HS256

**Prevention:**
```php
// Always validate algorithm
if ($token->headers()->get('alg') !== $expectedAlgorithm) {
    throw new TokenInvalidException('Algorithm mismatch');
}
```

### 2. None Algorithm

**Attack:** Set algorithm to "none" to bypass signature

**Prevention:**
- Never allow "none" algorithm
- Always validate signature

### 3. Weak Secret Keys

**Attack:** Brute force weak secrets

**Prevention:**
- Use cryptographically strong keys
- Minimum 256 bits for HMAC
- Use secure random generation

### 4. Token Leakage

**Attack:** Tokens exposed in logs, URLs, etc.

**Prevention:**
```php
// ❌ Never log tokens
$logger->info('User login', ['token' => $token]);

// ✅ Log safe information only
$logger->info('User login', ['user_id' => $userId, 'jti' => $jti]);
```

### 5. Replay Attacks

**Attack:** Reuse intercepted tokens

**Prevention:**
- Short token lifetimes
- Token blacklisting
- JTI (JWT ID) tracking

## Implementation Security

### Input Validation

```php
public function validateAccessToken(string $accessToken): JwtPayload
{
    // Validate input
    if (empty($accessToken)) {
        throw new TokenInvalidException('Token cannot be empty');
    }
    
    if (strlen($accessToken) > 8192) { // Reasonable limit
        throw new TokenInvalidException('Token too long');
    }
    
    // Continue with validation...
}
```

### Rate Limiting

```php
// Implement rate limiting for auth endpoints
class AuthRateLimitMiddleware
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $clientIp = $request->getClientIp();
        $key = "auth_rate_limit:{$clientIp}";
        
        $attempts = $this->cache->get($key, 0);
        if ($attempts >= 5) { // 5 attempts per minute
            throw new TooManyRequestsException('Rate limit exceeded');
        }
        
        $this->cache->set($key, $attempts + 1, 60);
        
        return $handler->handle($request);
    }
}
```

### Audit Logging

```php
public function generateTokenPair(string $subjectId, array $payload = []): TokenPair
{
    $tokenPair = $this->createTokenPair($subjectId, $payload);
    
    // Log security events
    $this->auditLogger->info('Token generated', [
        'subject_id' => $subjectId,
        'jti' => $tokenPair->getAccessTokenId(),
        'ip_address' => $this->request->getClientIp(),
        'user_agent' => $this->request->getHeaderLine('User-Agent'),
    ]);
    
    return $tokenPair;
}
```

## Security Headers

Add security headers to your responses:

```php
// In your middleware or controller
$response = $response
    ->withHeader('X-Content-Type-Options', 'nosniff')
    ->withHeader('X-Frame-Options', 'DENY')
    ->withHeader('X-XSS-Protection', '1; mode=block')
    ->withHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
```

## Monitoring and Alerting

### Track Security Events

```php
// Failed authentication attempts
$this->securityMonitor->recordFailedAuth($clientIp, $userAgent);

// Multiple token refresh attempts
$this->securityMonitor->recordSuspiciousRefresh($userId, $tokenCount);

// Token used after logout
$this->securityMonitor->recordRevokedTokenUse($jti, $clientIp);
```

### Alert Thresholds

- Multiple failed authentication attempts from same IP
- Excessive token refresh requests
- Use of revoked tokens
- Unusual access patterns

## Compliance Considerations

### GDPR
- Include user consent for token processing
- Implement right to erasure (delete all user tokens)
- Log processing activities

### PCI DSS
- Encrypt tokens in storage if handling payment data
- Implement strong access controls
- Regular security assessments

### HIPAA
- Encrypt tokens containing health information
- Implement audit trails
- Access control and user authentication

## Security Checklist

- [ ] Strong secret keys (256+ bits)
- [ ] HTTPS only in production
- [ ] Short access token lifetime (15-30 minutes)
- [ ] Token blacklisting enabled
- [ ] Input validation implemented
- [ ] Rate limiting on auth endpoints
- [ ] Audit logging configured
- [ ] Security headers added
- [ ] Regular key rotation schedule
- [ ] Monitoring and alerting setup
- [ ] Secure client-side storage
- [ ] Algorithm validation in place
- [ ] No tokens in logs or URLs
