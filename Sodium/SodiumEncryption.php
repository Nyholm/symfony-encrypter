<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Encryption\Sodium;

use Symfony\Component\Encryption\Ciphertext;
use Symfony\Component\Encryption\EncryptionInterface;
use Symfony\Component\Encryption\Exception\DecryptionException;
use Symfony\Component\Encryption\Exception\EncryptionException;
use Symfony\Component\Encryption\Exception\InvalidKeyException;
use Symfony\Component\Encryption\Exception\SignatureVerificationRequiredException;
use Symfony\Component\Encryption\Exception\UnableToVerifySignatureException;
use Symfony\Component\Encryption\Exception\UnsupportedAlgorithmException;
use Symfony\Component\Encryption\KeyInterface;

/**
 * Using the Sodium extension to safely encrypt your data.
 *
 * @author Tobias Nyholm <tobias.nyholm@gmail.com>
 *
 * @experimental in 5.3
 */
final class SodiumEncryption implements EncryptionInterface
{
    public function generateKey(string $secret = null): KeyInterface
    {
        return SodiumKey::create($secret ?? sodium_crypto_secretbox_keygen(), sodium_crypto_box_keypair());
    }

    public function encrypt(string $message, KeyInterface $key): string
    {
        if (!$key instanceof SodiumKey) {
            throw new InvalidKeyException(sprintf('Class "%s" will only accept key objects of class "%s".', self::class, SodiumKey::class));
        }

        $nonce = random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        try {
            $ciphertext = sodium_crypto_secretbox($message, $nonce, $key->getSecret());
        } catch (\SodiumException $exception) {
            throw new EncryptionException('Failed to encrypt message.', $exception);
        }

        return Ciphertext::create('sodium_secretbox', $ciphertext, $nonce)->getString();
    }

    public function encryptFor(string $message, KeyInterface $recipientKey): string
    {
        if (!$recipientKey instanceof SodiumKey) {
            throw new InvalidKeyException(sprintf('Class "%s" will only accept key objects of class "%s".', self::class, SodiumKey::class));
        }

        try {
            $ciphertext = sodium_crypto_box_seal($message, $recipientKey->getPublicKey());
        } catch (\SodiumException $exception) {
            throw new EncryptionException('Failed to encrypt message.', $exception);
        }

        return Ciphertext::create('sodium_crypto_box_seal', $ciphertext, random_bytes(\SODIUM_CRYPTO_BOX_NONCEBYTES))->getString();
    }

    public function encryptForAndSign(string $message, KeyInterface $recipientKey, KeyInterface $senderKey): string
    {
        if (!$recipientKey instanceof SodiumKey || !$senderKey instanceof SodiumKey) {
            throw new InvalidKeyException(sprintf('Class "%s" will only accept key objects of class "%s".', self::class, SodiumKey::class));
        }

        try {
            $nonce = random_bytes(\SODIUM_CRYPTO_BOX_NONCEBYTES);
            $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($senderKey->getPrivateKey(), $recipientKey->getPublicKey());
            $ciphertext = sodium_crypto_box($message, $nonce, $keypair);
        } catch (\SodiumException $exception) {
            throw new EncryptionException('Failed to encrypt message.', $exception);
        }

        return Ciphertext::create('sodium_crypto_box', $ciphertext, $nonce)->getString();
    }

    public function decrypt(string $message, KeyInterface $key, KeyInterface $senderPublicKey = null): string
    {
        if (!$key instanceof SodiumKey) {
            throw new InvalidKeyException(sprintf('Class "%s" will only accept key objects of class "%s".', self::class, SodiumKey::class));
        }

        $ciphertext = Ciphertext::parse($message);
        $algorithm = $ciphertext->getAlgorithm();
        $payload = $ciphertext->getPayload();
        $nonce = $ciphertext->getNonce();

        if (null !== $senderPublicKey && 'sodium_crypto_box' !== $algorithm) {
            throw new UnableToVerifySignatureException();
        }

        try {
            if ('sodium_crypto_box_seal' === $algorithm) {
                $output = sodium_crypto_box_seal_open($payload, $key->getKeypair());
            } elseif ('sodium_crypto_box' === $algorithm) {
                if (null === $senderPublicKey) {
                    throw new SignatureVerificationRequiredException();
                }
                $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($key->getPrivateKey(), $senderPublicKey->getPublicKey());
                $output = sodium_crypto_box_open($payload, $nonce, $keypair);
            } elseif ('sodium_secretbox' === $algorithm) {
                $output = sodium_crypto_secretbox_open($payload, $nonce, $key->getSecret());
            } else {
                throw new UnsupportedAlgorithmException($algorithm);
            }
        } catch (\SodiumException $exception) {
            throw new DecryptionException(sprintf('Failed to decrypt message with algorithm "%s".', $algorithm), $exception);
        }

        if (false === $output) {
            throw new DecryptionException();
        }

        return $output;
    }
}
