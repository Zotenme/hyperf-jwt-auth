<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Exception;

/**
 * Exception for invalid tokens.
 */
class TokenInvalidException extends JwtException
{
    public function __construct(string $message = 'Token is invalid', int $code = 401, ?\Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
