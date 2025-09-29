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

        // For ElGamal we want to ensure that `p` is chosen as a safeprime,
        // which ensures $Z^*_p$ cyclic group has a large prime order subgroup (q).
        while (true) {

            // We generate random prime with 1 bit length less than the key size
            qprime = BigInteger.probablePrime(bitLength - 1, random);

            // We choose pprime as our safe prime candidate: pprime = 2 * qprime + 1
            // If pprime will be prime with high confidence, then we assign p,q   
            pprime = qprime.multiply(BigInteger.TWO).add(BigInteger.ONE);
            if (pprime.isProbablePrime(100)) {
                break;
            }
        }
        this.q = qprime;
        this.p = pprime;
        
        // We want to find the G generator of a subgroup order q
        // in the multiplicative group modulo p
        this.g = findGenerator(p, q);
    }

    private static BigInteger findGenerator(BigInteger p, BigInteger q) {
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        while (true) {
            BigInteger g = new BigInteger(p.bitLength(), random);
            if (g.compareTo(BigInteger.TWO) < 0 || g.compareTo(pMinus1) >= 0) continue;

            // g^2 mod p != 1 and g^q mod p != 1
            // g will be a suitable generator for the subgroup if the following holds:
                // $g^2 \neq 1 \mod p$, ensures that g is not order of 2
                // $g^2 \neq 1 mod p$, ensures oderder is not dividing with q 
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

        // The modular inverse of an integer, let say `a` modulo `m` exists if and only if `gcd⁡(a,m)=1`
        // We check therefore if the BigInteger value we want to invert is coprime with the modulus 
        // before attempting the inversion (sInv):
        if (!s.gcd(p).equals(BigInteger.ONE)) {

            // In case gcd check fails we throw an exception due to s is not invertible modulo p.
            throw new IllegalStateException("GCD check failed: Decryption cannot proceed due to invalid ciphertext or key");
        }


        BigInteger sInv = s.modInverse(p);
        BigInteger mEncoded = ciphertext.c2.multiply(sInv).mod(p);

        // We assuming that the plaintext is restricted to {0,1} and  m is encoded as g^m mod p, where g is the generator. 
        if (mEncoded.equals(BigInteger.ONE)) {
             // If mEncoded equals 1, the message corresponds to m = 0 (since g^0 = 1).
            return BigInteger.ZERO;
            
        } else if (mEncoded.equals(g)) {
             // mEncoded equals g, the message corresponds to m = 1 (because g^1 = g).
            return BigInteger.ONE;
        } else {
            // In case mEncoded is neither 1 or g we throw an exception
            throw new IllegalStateException("Decryption failed: unexpected message value.");
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
