<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Encryption;

use Symfony\Component\Encryption\Exception\DecryptionException;
use Symfony\Component\Encryption\Exception\MalformedCipherException;

/**
 * This class is responsible over the payload API.
 *
 * @author Tobias Nyholm <tobias.nyholm@gmail.com>
 *
 * @internal
 */
class Ciphertext
{
    /**
     * @var string algorithm for the encryption
     */
    private $algorithm;

    /**
     * @var string
     */
    private $version;

    /**
     * @var string the encoded payload
     */
    private $payload;

    /**
     * @var string nonce for the algorithm
     */
    private $nonce;

    /**
     * @var array<string, string> additional headers
     */
    private $headers = [];

    private function __construct()
    {
    }

    /**
     * @param array<string, string> $headers with ascii keys and values
     */
    public static function create(string $algorithm, string $ciphertext, string $nonce, array $headers = []): self
    {
        $model = new self();
        $model->algorithm = $algorithm;
        $model->payload = $ciphertext;
        $model->nonce = $nonce;
        $model->headers = $headers;

        return $model;
    }

    /**
     * Take a string representation of the chiphertext and parse it into an object.
     *
     * @throws MalformedCipherException
     */
    public static function parse(string $input): self
    {
        $parts = explode('.', $input);
        if (!\is_array($parts) || 4 !== \count($parts)) {
            throw new MalformedCipherException();
        }

        [$headersString, $payload, $nonce, $hashSignature] = $parts;

        $headersString = self::base64UrlDecode($headersString);
        $payload = self::base64UrlDecode($payload);
        $nonce = self::base64UrlDecode($nonce);
        $hashSignature = self::base64UrlDecode($hashSignature);

        // Check if Authentication Tag is valid
        $hash = hash('sha256', $headersString.$payload.$nonce);
        if (!hash_equals($hash, $hashSignature)) {
            throw new MalformedCipherException();
        }

        $headers = json_decode($headersString, true);
        if (!\is_array($headers) || !\array_key_exists('alg', $headers) || !\array_key_exists('ver', $headers) || '1' !== $headers['ver']) {
            throw new MalformedCipherException();
        }

        $model = new self();
        $model->algorithm = $headers['alg'];
        unset($headers['alg']);
        unset($headers['ver']);
        $model->headers = $headers;
        $model->nonce = $nonce;
        $model->payload = $payload;

        return $model;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->getString();
    }

    public function getString(): string
    {
        $headers = json_encode(array_merge($this->headers, [
            'alg' => $this->algorithm,
            'ver' => '1',
        ]));

        return sprintf('%s.%s.%s.%s',
            self::base64UrlEncode($headers),
            self::base64UrlEncode($this->payload),
            self::base64UrlEncode($this->nonce),
            self::base64UrlEncode(hash('sha256', $headers.$this->payload.$this->nonce))
        );
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    public function getVersion(): string
    {
        return $this->version;
    }

    public function getPayload(): string
    {
        return $this->payload;
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }

    public function hasHeader(string $name): bool
    {
        return \array_key_exists($name, $this->headers);
    }

    public function getHeader(string $name): string
    {
        if ($this->hasHeader($name)) {
            return $this->headers[$name];
        }

        throw new DecryptionException(sprintf('The expected header "%s" is not found.', $name));
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        $decodedContent = base64_decode(strtr($data, '-_', '+/'), true);

        if (!\is_string($decodedContent)) {
            throw new MalformedCipherException('Could not base64 decode the content.');
        }

        return $decodedContent;
    }
}
