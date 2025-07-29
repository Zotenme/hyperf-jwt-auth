<?php

declare(strict_types=1);

namespace Zotenme\JwtAuth\Exception;

/**
 * Base exception for JWT operations.
 */
class JwtException extends \Exception
{
    public function __construct(string $message = '', int $code = 0, ?\Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
