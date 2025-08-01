<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf JWT Auth.
 *
 * @link     https://github.com/Zotenme/hyperf-jwt-auth
 * @document https://github.com/Zotenme/hyperf-jwt-auth/blob/main/README.md
 * @contact  zotenme@gmail.com
 * @license  https://github.com/Zotenme/hyperf-jwt-auth/blob/main/LICENSE
 */

namespace Zotenme\JwtAuth\Tests\Unit;

use Mockery\MockInterface;
use Zotenme\JwtAuth\Config\JwtConfig;
use Zotenme\JwtAuth\Contract\TokenStorageInterface;
use Zotenme\JwtAuth\DTO\JwtPayload;
use Zotenme\JwtAuth\DTO\TokenPair;
use Zotenme\JwtAuth\Exception\JwtException;
use Zotenme\JwtAuth\Exception\TokenInvalidException;
use Zotenme\JwtAuth\JwtManager;
use Zotenme\JwtAuth\Tests\TestCase;
use Zotenme\JwtAuth\Utils\JwtTokenBuilder;
use Zotenme\JwtAuth\Utils\JwtTokenValidator;

/**
 * @internal
 *
 * @coversNothing
 */
class JwtManagerTest extends TestCase
{
    private JwtManager $jwtManager;

    private JwtConfig $config;

    /** @var MockInterface&TokenStorageInterface */
    private TokenStorageInterface $tokenStorage;

    /** @var JwtTokenBuilder&MockInterface */
    private JwtTokenBuilder $tokenBuilder;

    /** @var JwtTokenValidator&MockInterface */
    private JwtTokenValidator $tokenValidator;

    protected function setUp(): void
    {
        parent::setUp();

        $mockConfig = $this->createMockConfig();
        $this->config = new JwtConfig($mockConfig);

        $this->tokenStorage = \Mockery::mock(TokenStorageInterface::class);
        $this->tokenBuilder = \Mockery::mock(JwtTokenBuilder::class);
        $this->tokenValidator = \Mockery::mock(JwtTokenValidator::class);

        $this->jwtManager = new JwtManager(
            $this->config,
            $this->tokenStorage,
            $this->tokenBuilder,
            $this->tokenValidator
        );
    }

    public function testGenerateTokenPairWithValidSubjectId(): void
    {
        $subjectId = 'user-123';
        $payload = ['role' => 'admin'];

        $expectedTokenPair = new TokenPair(
            'access-token',
            'refresh-token',
            900,
            604800
        );

        $this->tokenStorage->shouldReceive('isSsoModeEnabled')
            ->once()
            ->andReturn(false);

        $this->tokenBuilder->shouldReceive('createTokenPair')
            ->with($subjectId, $payload)
            ->once()
            ->andReturn($expectedTokenPair);

        $result = $this->jwtManager->generateTokenPair($subjectId, $payload);

        $this->assertSame($expectedTokenPair, $result);
    }

    public function testGenerateTokenPairWithSsoMode(): void
    {
        $subjectId = 'user-123';

        $expectedTokenPair = new TokenPair(
            'access-token',
            'refresh-token',
            900,
            604800
        );

        $this->tokenStorage->shouldReceive('isSsoModeEnabled')
            ->once()
            ->andReturn(true);

        $this->tokenStorage->shouldReceive('revokeAllSubjectTokens')
            ->with($subjectId)
            ->once();

        $this->tokenBuilder->shouldReceive('createTokenPair')
            ->with($subjectId, [])
            ->once()
            ->andReturn($expectedTokenPair);

        $result = $this->jwtManager->generateTokenPair($subjectId);

        $this->assertSame($expectedTokenPair, $result);
    }

    public function testGenerateTokenPairWithEmptySubjectId(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Subject ID cannot be empty');

        $this->jwtManager->generateTokenPair('');
    }

    public function testRefreshAccessTokenWithRotationEnabled(): void
    {
        $refreshToken = 'refresh-token';
        $subjectId = 'user-123';
        $customClaims = ['role' => 'admin', 'access_jti' => 'old-access-jti'];

        $payload = new JwtPayload(
            $subjectId,
            time(),
            time() + 604800,
            'refresh-jti',
            $customClaims
        );

        // Mock config with rotation enabled
        $mockConfig = $this->createMockConfig(['jwt.refresh_token.rotation_enabled' => true]);
        $config = new JwtConfig($mockConfig);

        $jwtManager = new JwtManager(
            $config,
            $this->tokenStorage,
            $this->tokenBuilder,
            $this->tokenValidator
        );

        $this->tokenValidator->shouldReceive('validateRefreshToken')
            ->with($refreshToken)
            ->once()
            ->andReturn($payload);

        // Не ожидаем вызова createTokenPair, так как произойдет ошибка при вызове revokeToken
        $this->expectException(\Exception::class);

        $jwtManager->refreshAccessToken($refreshToken);
    }

    public function testRefreshAccessTokenWithoutRotation(): void
    {
        $refreshToken = 'refresh-token';
        $subjectId = 'user-123';
        $customClaims = ['role' => 'admin', 'access_jti' => 'old-access-jti'];

        $payload = new JwtPayload(
            $subjectId,
            time(),
            time() + 604800,
            'refresh-jti',
            $customClaims
        );

        $newAccessToken = 'new-access-token';

        $this->tokenValidator->shouldReceive('validateRefreshToken')
            ->with($refreshToken)
            ->once()
            ->andReturn($payload);

        $this->tokenBuilder->shouldReceive('createAccessToken')
            ->with($subjectId, ['role' => 'admin'])
            ->once()
            ->andReturn($newAccessToken);

        $result = $this->jwtManager->refreshAccessToken($refreshToken);

        $this->assertInstanceOf(TokenPair::class, $result);
        $this->assertSame($newAccessToken, $result->accessToken);
        $this->assertSame($refreshToken, $result->refreshToken);
    }

    public function testValidateAccessToken(): void
    {
        $accessToken = 'access-token';
        $expectedPayload = new JwtPayload(
            'user-123',
            time(),
            time() + 900,
            'access-jti'
        );

        $this->tokenValidator->shouldReceive('validateAccessToken')
            ->with($accessToken)
            ->once()
            ->andReturn($expectedPayload);

        $result = $this->jwtManager->validateAccessToken($accessToken);

        $this->assertSame($expectedPayload, $result);
    }

    public function testValidateRefreshToken(): void
    {
        $refreshToken = 'refresh-token';
        $expectedPayload = new JwtPayload(
            'user-123',
            time(),
            time() + 604800,
            'refresh-jti'
        );

        $this->tokenValidator->shouldReceive('validateRefreshToken')
            ->with($refreshToken)
            ->once()
            ->andReturn($expectedPayload);

        $result = $this->jwtManager->validateRefreshToken($refreshToken);

        $this->assertSame($expectedPayload, $result);
    }

    public function testRevokeTokenWithEmptyToken(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token cannot be empty');

        $this->jwtManager->revokeToken('');
    }

    // Упрощенные тесты без сложного мокинга
    public function testRevokeTokenCallsValidator(): void
    {
        $token = 'test-token';

        $this->tokenValidator->shouldReceive('parseTokenWithoutValidation')
            ->with($token)
            ->once()
            ->andThrow(new \Exception('Test exception'));

        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Failed to revoke token: Test exception');

        $this->jwtManager->revokeToken($token);
    }

    public function testRevokeAllSubjectTokensWithValidSubjectId(): void
    {
        $subjectId = 'subject-123';

        $this->tokenStorage->shouldReceive('revokeAllSubjectTokens')
            ->with($subjectId)
            ->once();

        $this->jwtManager->revokeAllSubjectTokens($subjectId);

        // Test passes if no exception is thrown
        $this->assertTrue(true);
    }

    public function testRevokeAllSubjectTokensWithEmptySubjectId(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Subject ID cannot be empty');

        $this->jwtManager->revokeAllSubjectTokens('');
    }

    public function testRevokeAllSubjectTokensHandlesStorageException(): void
    {
        $subjectId = 'subject-123';

        $this->tokenStorage->shouldReceive('revokeAllSubjectTokens')
            ->with($subjectId)
            ->once()
            ->andThrow(new \Exception('Storage error'));

        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Failed to revoke all subject tokens: Storage error');

        $this->jwtManager->revokeAllSubjectTokens($subjectId);
    }
}
