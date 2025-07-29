<?php

declare(strict_types=1);


namespace extractor;

use Psr\Http\Message\ServerRequestInterface;
use Zotenme\JwtAuth\Exception\TokenInvalidException;

/**
 * Standard token extractor from HTTP headers.
 */
class TokenExtractor
{
    private const AUTHORIZATION_HEADER = 'Authorization';
    private const BEARER_PREFIX = 'Bearer ';

    /**
     * Extracts the token from the HTTP request.
     *
     * @param ServerRequestInterface $request HTTP request
     *
     * @return null|string Token or null if not found
     *
     * @throws TokenInvalidException If the token has an invalid format
     */
    public function extractToken(ServerRequestInterface $request): ?string
    {
        $authHeader = $this->getAuthorizationHeader($request);

        if ($authHeader === null) {
            return null;
        }

        // Remove extra spaces from the header
        $authHeader = trim($authHeader);

        // If the header starts with Bearer, but the token is empty - this is an error
        if (str_starts_with($authHeader, self::BEARER_PREFIX)) {
            $token = substr($authHeader, strlen(self::BEARER_PREFIX));
            $token = trim($token);

            if ($token === '') {
                throw new TokenInvalidException('Bearer token cannot be empty');
            }

            // Check that the token contains only valid characters
            if (!preg_match('/^[a-zA-Z0-9\-_\.]+$/', $token)) {
                throw new TokenInvalidException('Bearer token contains invalid characters');
            }

            return $token;
        }

        if (trim($authHeader) === 'Bearer') {
            // Case when the header contains only 'Bearer' without a token
            throw new TokenInvalidException('Bearer token cannot be empty');
        }

        // If not a Bearer scheme, return null
        return null;
    }

    /**
     * Retrieves the Authorization header from the request.
     *
     * @param ServerRequestInterface $request HTTP request
     *
     * @return null|string Header value or null
     */
    private function getAuthorizationHeader(ServerRequestInterface $request): ?string
    {
        $headers = $request->getHeader(self::AUTHORIZATION_HEADER);

        if (empty($headers)) {
            return null;
        }

        return $headers[0];
    }
}
