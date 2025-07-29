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

namespace Zotenme\JwtAuth\Factory;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as EcdsaSha384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as EcdsaSha512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HmacSha384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HmacSha512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RsaSha384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RsaSha512;
use Zotenme\JwtAuth\Config\JwtAlgorithm;
use Zotenme\JwtAuth\Config\JwtConfig;
use Zotenme\JwtAuth\Exception\JwtException;

/**
 * Factory for creating JWT configuration.
 */
class JwtConfigurationFactory
{
    public function __construct(
        private readonly JwtConfig $config
    ) {}

    /**
     * Creates the JWT configuration.
     */
    public function create(): Configuration
    {
        $algorithm = $this->config->getAlgorithm();
        $signer = $this->createSigner($algorithm);

        if ($algorithm->isSymmetric()) {
            return $this->createSymmetricConfiguration($signer);
        }

        return $this->createAsymmetricConfiguration($signer);
    }

    /**
     * Creates symmetric configuration for HMAC algorithms.
     */
    private function createSymmetricConfiguration(Signer $signer): Configuration
    {
        $secretKey = $this->config->getSecretKey();

        if (empty($secretKey)) {
            throw new JwtException('Secret key cannot be empty for HMAC algorithms');
        }

        $signingKey = InMemory::plainText($secretKey);

        return Configuration::forSymmetricSigner($signer, $signingKey);
    }

    /**
     * Creates asymmetric configuration for RSA/ECDSA algorithms.
     */
    private function createAsymmetricConfiguration(Signer $signer): Configuration
    {
        $privateKey = $this->config->getPrivateKey();

        if (empty($privateKey)) {
            throw new JwtException('Private key cannot be empty for asymmetric algorithms');
        }

        $publicKey = $this->config->getPublicKey();

        if (empty($publicKey)) {
            throw new JwtException('Public key cannot be empty for asymmetric algorithms');
        }

        $privateKeyObj = InMemory::plainText($privateKey, $this->config->getPassphrase());
        $publicKeyObj = InMemory::plainText($publicKey);

        return Configuration::forAsymmetricSigner($signer, $privateKeyObj, $publicKeyObj);
    }

    /**
     * Creates a signer for the algorithm.
     */
    private function createSigner(JwtAlgorithm $algorithm): Signer
    {
        return match ($algorithm) {
            JwtAlgorithm::HS256 => new HmacSha256(),
            JwtAlgorithm::HS384 => new HmacSha384(),
            JwtAlgorithm::HS512 => new HmacSha512(),
            JwtAlgorithm::RS256 => new RsaSha256(),
            JwtAlgorithm::RS384 => new RsaSha384(),
            JwtAlgorithm::RS512 => new RsaSha512(),
            JwtAlgorithm::ES256 => new EcdsaSha256(),
            JwtAlgorithm::ES384 => new EcdsaSha384(),
            JwtAlgorithm::ES512 => new EcdsaSha512(),
        };
    }
}
