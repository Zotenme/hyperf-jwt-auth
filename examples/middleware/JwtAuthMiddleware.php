<?php

declare(strict_types=1);


use extractor\TokenExtractor;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zotenme\JwtAuth\Contract\JwtManagerInterface;
use Zotenme\JwtAuth\Exception\TokenInvalidException;

/**
 * Middleware for JWT authentication.
 */
class JwtAuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private JwtManagerInterface $jwtManager,
        private TokenExtractor $tokenExtractor
    ) {
    }

    /**
     * Handles the HTTP request.
     *
     * @param ServerRequestInterface  $request HTTP request
     * @param RequestHandlerInterface $handler Request handler
     *
     * @return ResponseInterface HTTP response
     *
     * @throws TokenInvalidException if the token is missing or invalid
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->tokenExtractor->extractToken($request);

        if ($token === null) {
            throw new TokenInvalidException('Missing authorization token');
        }

        $payload = $this->jwtManager->validateAccessToken($token);

        // Add user data to request attributes
        $request = $request
            ->withAttribute('jwt_payload', $payload)
            ->withAttribute('jwt_token', $token)
            ->withAttribute('jwt_subject_id', $payload->subject)
            ->withAttribute('jwt_claims', $payload->toArray())
        ;

        return $handler->handle($request);
    }
}
