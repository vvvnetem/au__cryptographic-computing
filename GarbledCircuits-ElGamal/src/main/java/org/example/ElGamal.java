package org.example;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ElGamal {
    private static final SecureRandom random = new SecureRandom();
    private static final int BIT_LENGTH = 2048; // Safe prime length
    private static final int LABEL_LENGTH_BYTES = 16; // 128-bit wire labels

    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;

    public ElGamal() {
        BigInteger tempQ, tempP;
        do {
            tempQ = BigInteger.probablePrime(BIT_LENGTH - 1, random);
            tempP = tempQ.multiply(BigInteger.TWO).add(BigInteger.ONE);
        } while (!tempP.isProbablePrime(100));
        this.q = tempQ;
        this.p = tempP;
        this.g = findGenerator();
    }

    private BigInteger findGenerator() {
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        while (true) {
            BigInteger h = uniformRandom(BigInteger.TWO, p.subtract(BigInteger.TWO));
            BigInteger candidate = h.modPow(pMinusOne.divide(q), p);
            if (!candidate.equals(BigInteger.ONE)) {
                return candidate;
            }
        }
    }

    private static BigInteger uniformRandom(BigInteger min, BigInteger max) {
        BigInteger result;
        do {
            result = new BigInteger(max.bitLength(), random);
        } while (result.compareTo(min) < 0 || result.compareTo(max) > 0);
        return result;
    }

    // ----- Key Classes -----

    public static class PublicKey {
        public final BigInteger y;
        public PublicKey(BigInteger y) { this.y = y; }
    }

    public static class SecretKey {
        public final BigInteger x;
        public SecretKey(BigInteger x) { this.x = x; }
    }

    public static class KeyPair {
        public final PublicKey publicKey;
        public final SecretKey secretKey;
        public KeyPair(PublicKey pk, SecretKey sk) {
            this.publicKey = pk;
            this.secretKey = sk;
        }
    }

    public static class Ciphertext {
        public final BigInteger c;
        public final BigInteger d;
        public Ciphertext(BigInteger c, BigInteger d) {
            this.c = c;
            this.d = d;
        }
    }

    // ----- Key Generation -----

    public SecretKey generatePrivateKey() {
        BigInteger x;
        do {
            x = new BigInteger(q.bitLength(), random);
        } while (x.compareTo(BigInteger.ONE) <= 0 || x.compareTo(q.subtract(BigInteger.ONE)) >= 0);
        return new SecretKey(x);
    }

    public PublicKey generatePublicKey(SecretKey sk) {
        return new PublicKey(g.modPow(sk.x, p));
    }

    public KeyPair generateKeyPair() {
        SecretKey sk = generatePrivateKey();
        return new KeyPair(generatePublicKey(sk), sk);
    }

    // ----- Encryption / Decryption -----

    public Ciphertext encrypt(BigInteger message, PublicKey pk) {
        if (message.compareTo(BigInteger.ZERO) < 0 || message.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            throw new IllegalArgumentException("Message must be in [0, p-1]");
        }

        // Encode as (m+1)^q mod p
        BigInteger s = message.add(BigInteger.ONE).modPow(q, p);

        BigInteger M;
        if (s.equals(BigInteger.ONE)) {
            M = message.add(BigInteger.ONE).mod(p);
        } else {
            M = message.add(BigInteger.ONE).negate().mod(p);
        }

        BigInteger r;
        do {
            r = new BigInteger(q.bitLength(), random);
        } while (r.compareTo(BigInteger.ONE) <= 0 || r.compareTo(q.subtract(BigInteger.ONE)) >= 0);

        BigInteger c = g.modPow(r, p);
        BigInteger d = M.multiply(pk.y.modPow(r, p)).mod(p);
        return new Ciphertext(c, d);
    }

    public BigInteger decrypt(Ciphertext ct, SecretKey sk) {
        BigInteger cx = ct.c.modPow(sk.x, p);
        BigInteger cxInv = cx.modInverse(p);
        BigInteger M = ct.d.multiply(cxInv).mod(p);

        if (M.compareTo(q) <= 0) {
            return M.subtract(BigInteger.ONE).mod(p);
        } else {
            return p.subtract(M).subtract(BigInteger.ONE).mod(p);
        }
    }

    // Used to generate a "fake" public key for OT sender's dummy inputs
    public PublicKey oGen() {
        BigInteger r;
        do {
            r = new BigInteger(BIT_LENGTH, random);
        } while (r.compareTo(BigInteger.ONE) <= 0 || r.compareTo(p.subtract(BigInteger.ONE)) >= 0);

        BigInteger h = r.multiply(r).mod(p);
        return new PublicKey(h);
    }

    // ----- PRF: Garbled Circuits -----

    public static class PRF {
        private static final int BLOCK_SIZE = 16; // 128 bits

        /**
         * G(A, B, i) = SHA-256(A || B || i)
         * A and B are 16-byte labels (128 bits)
         * Output: 32-byte (256-bit) digest
         */
        public static byte[] compute(byte[] A, byte[] B, int i) {
            if (A.length != BLOCK_SIZE || B.length != BLOCK_SIZE) {
                throw new IllegalArgumentException("Inputs must be 16 bytes each");
            }

            try {
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                sha256.update(A);
                sha256.update(B);

                byte[] iBytes = ByteBuffer.allocate(4).putInt(i).array();
                sha256.update(iBytes);

                return sha256.digest();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("SHA-256 not available", e);
            }
        }
    }

    // ----- Getters -----

    public BigInteger getP() { return p; }
    public BigInteger getQ() { return q; }
    public BigInteger getG() { return g; }
}
