package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamal {
    private static final SecureRandom random = new SecureRandom();
    private static final int bitLength = 512; // Key size in bits

    private final BigInteger p; // safe prime p = 2q + 1
    private final BigInteger q; // large prime
    private final BigInteger g; // generator


    public ElGamal() {
        BigInteger qprime;
        BigInteger pprime;

        // Ensures we modInverse() will be invertable
        while (true) {
            qprime = BigInteger.probablePrime(bitLength - 1, random);
            pprime = qprime.multiply(BigInteger.TWO).add(BigInteger.ONE);
            if (pprime.isProbablePrime(100)) {
                break;
            }
        }
        this.q = qprime;
        this.p = pprime;
        this.g = findGenerator(p, q);
    }

    private static BigInteger findGenerator(BigInteger p, BigInteger q) {
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        while (true) {
            BigInteger g = new BigInteger(p.bitLength(), random);
            if (g.compareTo(BigInteger.TWO) < 0 || g.compareTo(pMinus1) >= 0) continue;

            // g^2 mod p != 1 and g^q mod p != 1
            if (!g.modPow(BigInteger.TWO, p).equals(BigInteger.ONE)
                    && !g.modPow(q, p).equals(BigInteger.ONE)) {
                return g;
            }
        }
    }

    public class PublicKey {
        public final BigInteger y;
        public PublicKey(BigInteger y) {
            this.y = y;
        }
    }

    public class SecretKey {
        public final BigInteger x;
        public SecretKey(BigInteger x) {
            this.x = x;
        }
    }

    public class KeyPair {
        public final PublicKey publicKey;
        public final SecretKey secretKey;
        public KeyPair(PublicKey publicKey, SecretKey secretKey) {
            this.publicKey = publicKey;
            this.secretKey = secretKey;
        }
    }

    public class Ciphertext {
        public final BigInteger c1;
        public final BigInteger c2;
        public Ciphertext(BigInteger c1, BigInteger c2) {
            this.c1 = c1;
            this.c2 = c2;
        }
    }

    public KeyPair generateKeyPair() {
        BigInteger x;
        do {
            x = new BigInteger(bitLength, random);
        } while (x.compareTo(BigInteger.ONE) <= 0 || x.compareTo(q.subtract(BigInteger.ONE)) >= 0);

        BigInteger y = g.modPow(x, p);
        return new KeyPair(new PublicKey(y), new SecretKey(x));
    }

    public Ciphertext encrypt(BigInteger message, PublicKey publicKey) {
        if (!message.equals(BigInteger.ZERO) && !message.equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("Only messages 0 or 1 are supported.");
        }

        BigInteger k;
        do {
            k = new BigInteger(bitLength, random);
        } while (k.compareTo(BigInteger.ONE) <= 0 || k.compareTo(q.subtract(BigInteger.ONE)) >= 0);

        BigInteger c1 = g.modPow(k, p);
        BigInteger c2 = publicKey.y.modPow(k, p).multiply(g.modPow(message, p)).mod(p);

        return new Ciphertext(c1, c2);
    }

    public BigInteger decrypt(Ciphertext ciphertext, SecretKey secretKey) {
        BigInteger s = ciphertext.c1.modPow(secretKey.x, p);

        // modInverse not invertable !

        if (!s.gcd(p).equals(BigInteger.ONE)) {
            throw new IllegalStateException("Decryption failed: s is not invertible modulo p.");
        }


        BigInteger sInv = s.modInverse(p);
        BigInteger mEncoded = ciphertext.c2.multiply(sInv).mod(p);

        // Now decode mEncoded = g^m mod p, and m should be 0 or 1
        if (mEncoded.equals(BigInteger.ONE)) {
            return BigInteger.ZERO;
        } else if (mEncoded.equals(g)) {
            return BigInteger.ONE;
        } else {
            throw new IllegalStateException("Decryption failed: unexpected message value.");
        }
    }

    public PublicKey oGen() {
        // Generate a dummy public key that looks like y = g^x mod p
        BigInteger dummyX;
        do {
            dummyX = new BigInteger(bitLength, random);
        } while (dummyX.compareTo(BigInteger.ONE) <= 0 || dummyX.compareTo(q.subtract(BigInteger.ONE)) >= 0);

        BigInteger y = g.modPow(dummyX, p);
        return new PublicKey(y);
    }
}
