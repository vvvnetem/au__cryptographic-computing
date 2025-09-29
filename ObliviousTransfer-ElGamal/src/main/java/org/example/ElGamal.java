package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamal {
    private static final SecureRandom random = new SecureRandom();
    private static final int bitLength = 512; // Key size in bits
    private static BigInteger p;
    private static BigInteger q;
    private static BigInteger g;

    public ElGamal() {
        // Generate a random prime q
        q = BigInteger.probablePrime(bitLength, random);
        //safe prime p = 2q + 1
        p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
        // Find a generator g (primitive root mod p)
        g = findGenerator(p);
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
        public final BigInteger c1;
        public final BigInteger c2;

        public Ciphertext(BigInteger c1, BigInteger c2) {
            this.c1 = c1;
            this.c2 = c2;
        }
    }

    public static SecretKey generatePrivateKey() {
        // Generate private key x (1 < x < q-1)
        BigInteger x;
        do {
            x = new BigInteger(bitLength, random);
        } while (x.compareTo(BigInteger.ONE) <= 0 || x.compareTo(q.subtract(BigInteger.ONE)) >= 0);

        return new SecretKey(x);
    }

    // Generate public key from private key
    public static PublicKey generatePublicKey(SecretKey secretKey) {
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
        // Generate random k (1 < k < q-1)
        BigInteger k;
        do {
            k = new BigInteger(bitLength, random);
        } while (k.compareTo(BigInteger.ONE) <= 0 || k.compareTo(q.subtract(BigInteger.ONE)) >= 0);

        // c1 = g^k mod p
        BigInteger c1 = g.modPow(k, p);

        // c2 = m * y^k mod p
        BigInteger c2 = message.multiply(publicKey.y.modPow(k, p)).mod(p);

        return new Ciphertext(c1, c2);
    }

    // Decrypt ciphertext using secret key
    public BigInteger decrypt(Ciphertext ciphertext, SecretKey secretKey) {
        // Compute c1^x mod p
        BigInteger c1x = ciphertext.c1.modPow(secretKey.x, p);

        // Compute modular inverse of c1^x
        BigInteger c1xInv = c1x.modInverse(p);

        // m = c2 * (c1^-x) mod p
        return ciphertext.c2.multiply(c1xInv).mod(p);
    }

 // Find a generator (primitive root) modulo p
private static BigInteger findGenerator(BigInteger p) {
    BigInteger pMinus1 = p.subtract(BigInteger.ONE);
    BigInteger q = pMinus1.divide(BigInteger.TWO); // since p = 2q + 1 (safe prime)

    while (true) {
        // random candidate g in [2, p-2]
        BigInteger g = new BigInteger(p.bitLength(), random);
        if (g.compareTo(BigInteger.ONE) <= 0 || g.compareTo(pMinus1) >= 0) {
            continue; // reject invalid ranges
        }

        // Check that g^2 mod p != 1 and g^q mod p != 1
        // These ensure g generates the group (primitive root modulo p)
        if (!g.modPow(BigInteger.TWO, p).equals(BigInteger.ONE) &&
            !g.modPow(q, p).equals(BigInteger.ONE)) {
            return g;
        }
    }
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
