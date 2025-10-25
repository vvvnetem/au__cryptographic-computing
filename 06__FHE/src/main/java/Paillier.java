import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Simple Paillier implementation (educational).
 *
 * - Key generation uses two primes p, q (each bits/2 length).
 * - Uses g = n + 1 (standard optimization).
 * - Encryption: c = g^m * r^n mod n^2.
 * - Decryption uses L(u) = (u-1)/n and mu.
 *
 * PublicKey contains n and g (and n^2 precomputed).
 */
public final class Paillier {
    private static final SecureRandom rnd = new SecureRandom();

    public static final class PublicKey {
        public final BigInteger n;
        public final BigInteger n2; // n^2
        public final BigInteger g;
        public PublicKey(BigInteger n, BigInteger g) { this.n = n; this.g = g; this.n2 = n.multiply(n); }
    }

    public static final class PrivateKey {
        // lambda = lcm(p-1, q-1), mu = L(g^lambda mod n^2)^{-1} mod n
        private final BigInteger lambda;
        private final BigInteger mu;
        private final BigInteger n;
        private PrivateKey(BigInteger lambda, BigInteger mu, BigInteger n) { this.lambda = lambda; this.mu = mu; this.n = n; }
    }

    public static final class KeyPair {
        private final PublicKey pub;
        private final PrivateKey priv;

        public KeyPair(PublicKey pub, PrivateKey priv) { this.pub = pub; this.priv = priv; }

        // Add these getters
        public PublicKey getPublic() { return pub; }
        public PrivateKey getPrivate() { return priv; }
    }
    public static final class Ciphertext {
        public final BigInteger c;
        public Ciphertext(BigInteger c) { this.c = c; }
    }

    // ---------- Key generation ----------
    public static KeyPair keyGen(int bits) {
        // choose two primes p,q each ~ bits/2
        BigInteger p = BigInteger.probablePrime(bits/2, rnd);
        BigInteger q;
        do {
            q = BigInteger.probablePrime(bits/2, rnd);
        } while (q.equals(p));
        BigInteger n = p.multiply(q);
        BigInteger n2 = n.multiply(n);

        BigInteger lambda = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
        // use g = n + 1 (convenient)
        BigInteger g = n.add(BigInteger.ONE);

        // compute mu = (L(g^lambda mod n^2))^-1 mod n
        BigInteger u = g.modPow(lambda, n2);
        BigInteger L = u.subtract(BigInteger.ONE).divide(n);
        BigInteger mu = L.modInverse(n);

        PublicKey pub = new PublicKey(n, g);
        PrivateKey priv = new PrivateKey(lambda, mu, n);
        return new KeyPair(pub, priv);
    }

    private static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.divide(a.gcd(b)).multiply(b);
    }

    // ---------- Encryption ----------
    // Encrypt small plaintext m (0/1 or small integers). Uses fresh random r in Z_n^*.
    public static Ciphertext encrypt(BigInteger m, PublicKey pk) {
        BigInteger n = pk.n;
        BigInteger n2 = pk.n2;
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.compareTo(BigInteger.ONE) <= 0 || !r.gcd(n).equals(BigInteger.ONE));
        // c = g^m * r^n mod n^2
        BigInteger c1 = pk.g.modPow(m, n2);
        BigInteger c2 = r.modPow(n, n2);
        BigInteger c = c1.multiply(c2).mod(n2);
        return new Ciphertext(c);
    }

    // Convenience encrypt with int
    public static Ciphertext encryptInt(int m, PublicKey pk) {
        return encrypt(BigInteger.valueOf(m), pk);
    }

    // ---------- Decryption ----------
    public static BigInteger decrypt(Ciphertext ct, KeyPair kp) {
        BigInteger n = kp.pub.n;
        BigInteger n2 = kp.pub.n2;
        BigInteger lambda = kp.priv.lambda;
        BigInteger mu = kp.priv.mu;
        BigInteger u = ct.c.modPow(lambda, n2);
        BigInteger L = u.subtract(BigInteger.ONE).divide(n);
        return L.multiply(mu).mod(n);
    }

    // ---------- Homomorphic helpers ----------
    // Enc(a) ⊕ Enc(b) = Enc(a + b)
    public static Ciphertext add(Ciphertext a, Ciphertext b, PublicKey pk) {
        return new Ciphertext(a.c.multiply(b.c).mod(pk.n2));
    }

    // Enc(a) * k (plaintext scalar multiply): Enc(a)^k = Enc(k*a)
    public static Ciphertext scalarMul(Ciphertext a, BigInteger k, PublicKey pk) {
        return new Ciphertext(a.c.modPow(k, pk.n2));
    }

    // Modular inverse of ciphertext under n^2: Enc(-m) = Enc(m)^{-1}
    public static Ciphertext neg(Ciphertext a, PublicKey pk) {
        return new Ciphertext(a.c.modInverse(pk.n2));
    }
}
