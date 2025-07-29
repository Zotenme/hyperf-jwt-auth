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
