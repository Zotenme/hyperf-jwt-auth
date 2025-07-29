<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Exception;

/**
 * Exception for expired tokens.
 */
class TokenExpiredException extends JwtException
{
    public function __construct(string $message = 'Token has expired', int $code = 401, ?\Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
