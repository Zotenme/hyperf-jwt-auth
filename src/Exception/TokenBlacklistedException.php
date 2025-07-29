<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Exception;

/**
 * Exception for blacklisted tokens.
 */
class TokenBlacklistedException extends JwtException
{
    public function __construct(string $message = 'Token is blacklisted', int $code = 401, ?\Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
