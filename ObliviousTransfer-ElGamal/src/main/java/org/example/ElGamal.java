package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamal {
    private static final SecureRandom random = new SecureRandom();
    private static final int bitLength = 512; // Key size in bits
    private  BigInteger p;
    private  BigInteger q;
    private  BigInteger g;

    public ElGamal() {
        do {
            // Generate prime q
            this.q = BigInteger.probablePrime(bitLength - 1, random);
            // Check if p = 2q + 1 is also prime
            this.p = q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
        } while (!p.isProbablePrime(20));

        // Find a generator g (primitive root mod p)
        findGenerator();
    }


    private void findGenerator() {
        // For safe prime p = 2q + 1, we need generator of subgroup of order q
        // Start with 2 and find element of order q
        BigInteger candidate = BigInteger.valueOf(2);

        while (true) {
            // Check if candidate^q mod p = 1 and candidate^1 mod p != 1
            if (candidate.modPow(q, p).equals(BigInteger.ONE) &&
                    !candidate.modPow(BigInteger.ONE, p).equals(BigInteger.ONE)) {
                this.g = candidate;
                break;
            }
            candidate = candidate.add(BigInteger.ONE);

            // Safety check to avoid infinite loop
            if (candidate.compareTo(p) >= 0) {
                throw new RuntimeException("Could not find generator for subgroup");
            }
        }
    }

    // Public key class
    public static class PublicKey {
        public final BigInteger y;      // public key component

        public PublicKey(BigInteger y) {
            this.y = y;
        }
    }

    // Private key class
    public static class SecretKey {
        public final BigInteger x;      // secret key

        public SecretKey(BigInteger x) {
            this.x = x;
        }
    }

    // Key pair class
    public static class KeyPair {
        public final PublicKey publicKey;
        public final SecretKey secretKey;

        public KeyPair(PublicKey publicKey, SecretKey secretKey) {
            this.publicKey = publicKey;
            this.secretKey = secretKey;
        }
    }

    // Ciphertext pair
    public static class Ciphertext {
        public final BigInteger c;
        public final BigInteger d;

        public Ciphertext(BigInteger c, BigInteger d) {
            this.c = c;
            this.d = d;
        }
    }

    public SecretKey generatePrivateKey() {
        // Generate private key x (1 < x < q-1)
        BigInteger x;
        do {
            x = new BigInteger(bitLength, random);
        } while (x.compareTo(BigInteger.ONE) <= 0 || x.compareTo(q.subtract(BigInteger.ONE)) >= 0);

        return new SecretKey(x);
    }

    // Generate public key from private key
    public PublicKey generatePublicKey(SecretKey secretKey) {
        // Compute public key y = g^x mod p
        BigInteger y = g.modPow(secretKey.x, p);

        return new PublicKey(y);
    }

    // Generate complete key pair
    public KeyPair generateKeyPair() {
        SecretKey secretKey = generatePrivateKey();
        PublicKey publicKey = generatePublicKey(secretKey);
        return new KeyPair(publicKey, secretKey);
    }

    // Encrypt message using public key
    public Ciphertext encrypt(BigInteger message, PublicKey publicKey) {
        if (message.compareTo(p) >= 0) {
            throw new IllegalArgumentException("Message must be less than p");
        }
        // Generate random k (1 < r < q-1)
        BigInteger r;
        do {
            r = new BigInteger(bitLength, random);
        } while (r.compareTo(BigInteger.ONE) <= 0 || r.compareTo(q.subtract(BigInteger.ONE)) >= 0);

        // c = g^r mod p
        BigInteger c = g.modPow(r, p);

        // d = m * y^k mod p
        BigInteger d = message.multiply(publicKey.y.modPow(r, p)).mod(p);

        return new Ciphertext(c, d);
    }

    // Decrypt ciphertext using secret key
    public BigInteger decrypt(Ciphertext ciphertext, SecretKey secretKey) {
        // Compute c^x mod p
        BigInteger cx = ciphertext.c.modPow(secretKey.x, p);

        // Compute modular inverse of c1^x
        BigInteger cxInv = cx.modInverse(p);

        // m = c2 * (c1^-x) mod p
        return ciphertext.d.multiply(cxInv).mod(p);
    }

    public PublicKey oGen() {
        // Generate random s (1 < s < p-1)
        BigInteger s;
        do {
            s = new BigInteger(bitLength, random);
        } while (s.compareTo(BigInteger.ONE) <= 0 || s.compareTo(p.subtract(BigInteger.ONE)) >= 0);

        BigInteger h = s.multiply(s).mod(p);
        return new PublicKey(h);
    }
}
