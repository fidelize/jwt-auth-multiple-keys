<?php
namespace Fidelize\JWTAuth;

use Exception;
use Log;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log as FacadesLog;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;
use PHPOpenSourceSaver\JWTAuth\Providers\JWT\Lcobucci;
use PHPOpenSourceSaver\JWTAuth\Contracts\Providers\JWT;


class JwtAdapter extends Lcobucci implements JWT
{   
    public function __construct()
    {
        return parent::__construct(
            Config::get('jwt.secret'),
            Config::get('jwt.algo'),
            []
        );
    }

    /**
     * Create a JSON Web Token.
     *
     * @return string
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload)
    {
        $this->builder = null;
        $this->builder = $this->config->builder();

        try {
            foreach ($payload as $key => $value) {
                if ($value === null) {
                    continue;
                }
                $this->addClaim($key, $value);
            }
            $key = $this->getPrivateKey();
            $signer = new RS256();

            if (!is_object($key)) {
                $signer = new HS256();
                $key = InMemory::plainText($key);
            }
            
            $token = $this->builder->getToken($signer, $key);
            return $token->toString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: ' . $e->getMessage());
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     * @return array
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function decode($token)
    {
        try {
            $jwt = $this->config->parser()->parse($token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage());
        }

        $claims = $jwt->claims()->all();

        if (array_key_exists('iss', $claims)) {
            if ($this->validateIss($jwt, $claims)) {
                return $this->getClaims($claims);
            }
        }

        // Test token signature against all available public keys + JWT secret
        $atLeastOnePublicKeyWorked = false;

        foreach ($this->getPublicKeys() as $publicKey) {
            $signer = new RS256();

            if (!is_object($publicKey)) {
                $signer = new HS256();
                $publicKey = InMemory::plainText($publicKey);
            }

            $this->config->setValidationConstraints(new SignedWith($signer, $publicKey));
            if ($this->config->validator()->validate($jwt, ...$this->config->validationConstraints())) {
                $atLeastOnePublicKeyWorked = true;
                break;
            }
                
        }

        if (!$atLeastOnePublicKeyWorked) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        // Convert to plain scalar values instead of an array of Claim objects
        return $this->getClaims($claims);
    }

    private function validateIss($jwt, $claims) {
        $iss = trim($this->getClaimValue($claims['iss']));
        $issuer = preg_replace('/[^A-Z0-9]+/', '_', strtoupper($iss));

        if (!$publicKey = $this->getPublicKeysFromEnv($issuer)) {
            return false;
        }

        $this->config->setValidationConstraints(new SignedWith(new RS256(), InMemory::plainText($publicKey)));
        if ($this->config->validator()->validate($jwt, ...$this->config->validationConstraints())) {
            return true;
        }

        return false;
    }

    /**
     * PRIVATE key is used to generate new tokens. In order to be trusted,
     * the system receiving the token must validate it against the PUBLIC key.
     */
    public function getPrivateKey()
    {
        $files = $this->globKeys('jwt.*.key');

        if (count($files) > 1) {
            throw new TokenInvalidException('Multiple private keys found.');
        }

        // If there is no private key, fallback to JWT_SECRET
        if (count($files) == 0) {
            return $this->config->signingKey()->contents();
        }

        $file = array_pop($files);
        return InMemory::file($file);
    }

    /**
     * PUBLIC keys against which it will try to validate and trust the token.
     * Note that though you can trust and use the token, you are not able
     * to generate tokens using PUBLIC keys, only PRIVATE ones.
     */
    private function getPublicKeys(): array
    {
        $files = $this->globKeys('jwt.*.key.pub');
        $keys = [];

        foreach ($files as $file) {
            $keys[] = InMemory::file($file);
        }

        // If there is no public key, fallback to JWT_SECRET
        $keys[] = $this->config->signingKey()->contents();

        return $keys;
    }

    private function getPublicKeysFromEnv($iss)
    {
        $env = getenv('JWT_PUBLIC_KEY_' . $iss);
        return base64_decode($env);
    }

    private function globKeys($pattern)
    {
        return File::glob($this->getKeysDirectory() . $pattern);
    }

    private function getKeysDirectory()
    {
        return Config::get('jwt.keys_directory') . DIRECTORY_SEPARATOR;
    }

    private function getClaims($claims): array
    {
        return (new Collection($claims))->map(function ($claim) {
            return $this->getClaimValue($claim);
        })->toArray();
    }

    private function getClaimValue($claim)
    {
        if (is_a($claim, \DateTimeImmutable::class)) {
            return $claim->getTimestamp();
        }
        if (is_object($claim) && method_exists($claim, 'getValue')) {
            return $claim->getValue();
        }

        return $claim;
    }
}
