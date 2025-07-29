<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Tests\Unit\Exception;

use Zotenme\JwtAuth\Exception\JwtException;
use Zotenme\JwtAuth\Exception\TokenBlacklistedException;
use Zotenme\JwtAuth\Exception\TokenExpiredException;
use Zotenme\JwtAuth\Exception\TokenInvalidException;
use Zotenme\JwtAuth\Tests\TestCase;

class ExceptionTest extends TestCase
{
    public function testJwtException(): void
    {
        $exception = new JwtException('Test message', 500);

        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertSame('Test message', $exception->getMessage());
        $this->assertSame(500, $exception->getCode());
    }

    public function testJwtExceptionWithPrevious(): void
    {
        $previous = new \RuntimeException('Previous exception');
        $exception = new JwtException('Test message', 500, $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testTokenExpiredException(): void
    {
        $exception = new TokenExpiredException();

        $this->assertInstanceOf(JwtException::class, $exception);
        $this->assertSame('Token has expired', $exception->getMessage());
        $this->assertSame(401, $exception->getCode());
    }

    public function testTokenExpiredExceptionWithCustomMessage(): void
    {
        $exception = new TokenExpiredException('Custom expired message', 403);

        $this->assertSame('Custom expired message', $exception->getMessage());
        $this->assertSame(403, $exception->getCode());
    }

    public function testTokenInvalidException(): void
    {
        $exception = new TokenInvalidException();

        $this->assertInstanceOf(JwtException::class, $exception);
        $this->assertSame('Token is invalid', $exception->getMessage());
        $this->assertSame(401, $exception->getCode());
    }

    public function testTokenInvalidExceptionWithCustomMessage(): void
    {
        $exception = new TokenInvalidException('Custom invalid message', 422);

        $this->assertSame('Custom invalid message', $exception->getMessage());
        $this->assertSame(422, $exception->getCode());
    }

    public function testTokenBlacklistedException(): void
    {
        $exception = new TokenBlacklistedException();

        $this->assertInstanceOf(JwtException::class, $exception);
        $this->assertSame('Token is blacklisted', $exception->getMessage());
        $this->assertSame(401, $exception->getCode());
    }

    public function testTokenBlacklistedExceptionWithCustomMessage(): void
    {
        $exception = new TokenBlacklistedException('Custom blacklisted message', 403);

        $this->assertSame('Custom blacklisted message', $exception->getMessage());
        $this->assertSame(403, $exception->getCode());
    }
}
