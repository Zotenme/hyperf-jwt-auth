<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Tests\Unit\Config;

use Zotenme\JwtAuth\Config\JwtAlgorithm;
use Zotenme\JwtAuth\Tests\TestCase;

class JwtAlgorithmTest extends TestCase
{
    public function testGetSupportedAlgorithms(): void
    {
        $supported = JwtAlgorithm::getSupported();

        $this->assertIsArray($supported);
        $this->assertContains('HS256', $supported);
        $this->assertContains('HS384', $supported);
        $this->assertContains('HS512', $supported);
        $this->assertContains('RS256', $supported);
        $this->assertContains('RS384', $supported);
        $this->assertContains('RS512', $supported);
        $this->assertContains('ES256', $supported);
        $this->assertContains('ES384', $supported);
        $this->assertContains('ES512', $supported);
    }

    public function testFromValidAlgorithm(): void
    {
        $algorithm = JwtAlgorithm::from('HS256');
        $this->assertInstanceOf(JwtAlgorithm::class, $algorithm);
        $this->assertSame('HS256', $algorithm->value);
    }

    public function testFromInvalidAlgorithm(): void
    {
        $this->expectException(\ValueError::class);
        $this->expectExceptionMessage('"INVALID" is not a valid backing value for enum');

        $invalidValue = 'INVALID';
        $result = JwtAlgorithm::from($invalidValue);

        // This line should never be reached due to the exception above
        $this->fail('Expected ValueError was not thrown');
    }

    public function testIsSymmetricForHmacAlgorithms(): void
    {
        $this->assertTrue(JwtAlgorithm::HS256->isSymmetric());
        $this->assertTrue(JwtAlgorithm::HS384->isSymmetric());
        $this->assertTrue(JwtAlgorithm::HS512->isSymmetric());
    }

    public function testIsSymmetricForAsymmetricAlgorithms(): void
    {
        $this->assertFalse(JwtAlgorithm::RS256->isSymmetric());
        $this->assertFalse(JwtAlgorithm::RS384->isSymmetric());
        $this->assertFalse(JwtAlgorithm::RS512->isSymmetric());
        $this->assertFalse(JwtAlgorithm::ES256->isSymmetric());
        $this->assertFalse(JwtAlgorithm::ES384->isSymmetric());
        $this->assertFalse(JwtAlgorithm::ES512->isSymmetric());
    }

    public function testToString(): void
    {
        $this->assertSame('HS256', JwtAlgorithm::HS256->value);
        $this->assertSame('RS256', JwtAlgorithm::RS256->value);
        $this->assertSame('ES256', JwtAlgorithm::ES256->value);
    }
}
