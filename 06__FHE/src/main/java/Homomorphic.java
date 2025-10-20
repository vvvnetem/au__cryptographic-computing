import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Tiny leveled homomorphic scheme (toy) with multiplicative depth control.
 *
 * Boolean ops: xor, eqBit, and, or, not, scalarMultiplyPlain.
 */
public final class Homomorphic {

    public static final int MAX_DEPTH = 3;

    private Homomorphic() { }

    public static class PublicKey { }
    public static class PrivateKey {
        private final BigInteger s;
        private PrivateKey(BigInteger s) { this.s = s; }
        public BigInteger getS() { return s; }
    }
    public static class KeyPair {
        private final PublicKey pub;
        private final PrivateKey priv;
        public KeyPair(PublicKey pub, PrivateKey priv) { this.pub = pub; this.priv = priv; }
        public PublicKey getPublic() { return pub; }
        public PrivateKey getPrivate() { return priv; }
    }

    public static class Ciphertext {
        public final BigInteger ct;
        public final int depth;
        public Ciphertext(BigInteger ct, int depth) { this.ct = ct; this.depth = depth; }
    }

    public static KeyPair genKeyPair(int secretBitLength, SecureRandom rnd) {
        BigInteger s;
        do {
            s = new BigInteger(secretBitLength, rnd);
        } while (s.compareTo(BigInteger.ONE) <= 0);
        if (!s.testBit(0)) s = s.setBit(0);
        return new KeyPair(new PublicKey(), new PrivateKey(s));
    }

    public static Ciphertext encrypt(BigInteger m, KeyPair kp, SecureRandom rnd) {
        BigInteger s = kp.getPrivate().getS();
        BigInteger r = new BigInteger(s.bitLength(), rnd);
        BigInteger ct = m.add(s.multiply(r));
        return new Ciphertext(ct, 0);
    }

    public static BigInteger decrypt(Ciphertext c, PrivateKey sk) {
        return c.ct.mod(sk.getS());
    }

    public static Ciphertext add(Ciphertext a, Ciphertext b, PublicKey pk, SecureRandom rnd) {
        return new Ciphertext(a.ct.add(b.ct), Math.max(a.depth, b.depth));
    }

    public static Ciphertext scalarMultiplyPlain(Ciphertext a, long k, PublicKey pk) {
        return new Ciphertext(a.ct.multiply(BigInteger.valueOf(k)), a.depth);
    }

    public static Ciphertext multiply(Ciphertext a, Ciphertext b, PublicKey pk, SecureRandom rnd) {
        int newDepth = a.depth + b.depth + 1;
        if (newDepth > MAX_DEPTH) throw new IllegalStateException("Multiplicative depth exceeded: " + newDepth);
        return new Ciphertext(a.ct.multiply(b.ct), newDepth);
    }

    public static Ciphertext and(Ciphertext a, Ciphertext b, PublicKey pk, SecureRandom rnd) {
        return multiply(a, b, pk, rnd);
    }

    public static Ciphertext or(Ciphertext a, Ciphertext b, PublicKey pk, SecureRandom rnd) {
        // OR(a,b) = a + b - a*b
        Ciphertext ab = multiply(a, b, pk, rnd);
        Ciphertext tmp = add(a, b, pk, rnd);
        return add(tmp, scalarMultiplyPlain(ab, -1, pk), pk, rnd);
    }

    public static Ciphertext not(Ciphertext a, Ciphertext encOne, PublicKey pk, SecureRandom rnd) {
        return add(encOne, scalarMultiplyPlain(a, -1, pk), pk, rnd);
    }

    public static Ciphertext xor(Ciphertext a, Ciphertext b, PublicKey pk, SecureRandom rnd) {
        // XOR(a,b) = a + b - 2*a*b
        Ciphertext ab = multiply(a, b, pk, rnd);
        Ciphertext twoAB = scalarMultiplyPlain(ab, 2, pk);
        return add(add(a, b, pk, rnd), scalarMultiplyPlain(twoAB, -1, pk), pk, rnd);
    }

    public static Ciphertext eqBit(Ciphertext x, Ciphertext y, Ciphertext encOne, PublicKey pk, SecureRandom rnd) {
        return not(xor(x, y, pk, rnd), encOne, pk, rnd);
    }
}
