import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Simple d-HE (vDGHV-inspired) educational implementation.
 *
 * Public key: y_i = p * q_i + 2 * r_i  (i = 1..n)
 * Secret key: p (odd)
 *
 * Encryption of bit m: choose subset S ⊆ {1..n}, compute
 *   c = m + sum_{i in S} y_i    (integer)
 *
 * Decryption: m = ((c mod p) mod 2)
 *
 * Ciphertext stores:
 *  - the integer c
 *  - an upper bound noiseBound on the "noise term" (≈ 2 * sum r_i and growth from multiplies)
 *  - the multiplicative level (depth)
 *
 * This is a **toy** implementation for learning and must not be used in production.
 */
public final class DHE {
    private static final SecureRandom SR = new SecureRandom();
    public static final boolean DEBUG = true;

    public static final class PublicKey {
        public final BigInteger[] y; // public y_i
        public final int n;
        public PublicKey(BigInteger[] y) { this.y = y; this.n = y.length; }
    }

    public static final class PrivateKey {
        public final BigInteger p;
        private PrivateKey(BigInteger p) { this.p = p; }
    }

    public static final class KeyPair {
        private final PublicKey pub;
        private final PrivateKey priv;
        public KeyPair(PublicKey pub, PrivateKey priv) { this.pub = pub; this.priv = priv; }
        public PublicKey getPublic() { return pub; }
        public PrivateKey getPrivate() { return priv; }
    }

    public static final class Ciphertext {
        public final BigInteger c;            // ciphertext integer
        public final BigInteger noiseBound;   // estimated upper bound on noise
        public final int level;               // multiplicative level (depth)

        public Ciphertext(BigInteger c, BigInteger noiseBound, int level) {
            this.c = c;
            this.noiseBound = noiseBound;
            this.level = level;
        }

        // convenience constructor
        public Ciphertext(BigInteger c) { this(c, BigInteger.ZERO, 0); }
    }

    // -------------------------
    // Key generation
    // -------------------------
    public static KeyPair keyGen(int pBits, int qBits, int rBits, int n, SecureRandom rnd) {
        BigInteger p = BigInteger.probablePrime(pBits, rnd);
        BigInteger[] y = new BigInteger[n];
        BigInteger[] rvals = new BigInteger[n];

        for (int i = 0; i < n; i++) {
            BigInteger qi = new BigInteger(qBits, rnd);
            BigInteger ri = new BigInteger(rBits, rnd);
            if (ri.signum() < 0) ri = ri.negate();
            rvals[i] = ri;
            y[i] = p.multiply(qi).add(ri.shiftLeft(1)); // p*qi + 2*ri
        }

        PublicKey pub = new PublicKey(y);
        PrivateKey priv = new PrivateKey(p);
        InternalStore.store(pub, rvals, rnd);

        if (DEBUG) {
            System.out.printf("[DHE.keyGen] pBits=%d, qBits=%d, rBits=%d, n=%d, sample y0 bits=%d%n",
                    pBits, qBits, rBits, n, y[0].bitLength());
        }

        return new KeyPair(pub, priv);
    }

    // -------------------------
    // Encryption
    // -------------------------
    public static Ciphertext encryptBit(int m, PublicKey pub, SecureRandom rnd, int sSize) {
        if (m != 0 && m != 1) throw new IllegalArgumentException("m must be 0 or 1");
        int n = pub.n;
        boolean[] inS = randomSubset(n, sSize, rnd);

        BigInteger sumY = BigInteger.ZERO;
        BigInteger sumR = BigInteger.ZERO;
        BigInteger[] rvals = InternalStore.getR(pub);

        for (int i = 0; i < n; i++) {
            if (inS[i]) {
                sumY = sumY.add(pub.y[i]);
                if (rvals != null) sumR = sumR.add(rvals[i]);
            }
        }
        BigInteger c = BigInteger.valueOf(m).add(sumY);
        BigInteger noiseBound = sumR.shiftLeft(1); // 2 * sum r_i

        if (DEBUG) {
            System.out.printf("[DHE.encrypt] m=%d | sSize=%d | noiseBound≈%s | level=0%n",
                    m, sSize, noiseBound.toString());
        }

        return new Ciphertext(c, noiseBound, 0);
    }

    private static boolean[] randomSubset(int n, int sSize, SecureRandom rnd) {
        boolean[] inS = new boolean[n];
        if (sSize <= 0 || sSize >= n) {
            for (int i = 0; i < n; i++) inS[i] = rnd.nextBoolean();
            return inS;
        }
        java.util.List<Integer> idx = new java.util.ArrayList<>(n);
        for (int i = 0; i < n; i++) idx.add(i);
        java.util.Collections.shuffle(idx, rnd);
        for (int i = 0; i < sSize; i++) inS[idx.get(i)] = true;
        return inS;
    }

    // -------------------------
    // Homomorphic addition
    // -------------------------
    public static Ciphertext add(Ciphertext a, Ciphertext b, PublicKey pub) {
        BigInteger c = a.c.add(b.c);
        BigInteger newNoise = a.noiseBound.add(b.noiseBound);
        int newLevel = Math.max(a.level, b.level);

        if (DEBUG) {
            System.out.printf("[DHE.add] level=%d+%d -> %d | noise≈%s%n",
                    a.level, b.level, newLevel, newNoise.toString());
        }

        return new Ciphertext(c, newNoise, newLevel);
    }

    // -------------------------
    // Homomorphic multiplication
    // -------------------------
    public static Ciphertext multiply(Ciphertext a, Ciphertext b, PublicKey pub, PrivateKey priv) {
        BigInteger c = a.c.multiply(b.c);

        // Tighter noise formula for bits {0,1} to prevent exponential growth
        BigInteger R1 = a.noiseBound;
        BigInteger R2 = b.noiseBound;
        BigInteger Rprime = R1.add(R2); // safe for 0/1 plaintexts

        int newLevel = a.level + b.level + 1;
        BigInteger p = priv.p;

        if (Rprime.shiftLeft(1).compareTo(p) >= 0) {
            throw new IllegalStateException("Noise bound exceeded: 2*R' >= p (2*R'=" + Rprime.shiftLeft(1) + ")");
        }

        if (DEBUG) {
            System.out.printf("[DHE.multiply] levels=%d+%d+1 -> %d | R1≈%s R2≈%s R'≈%s | pBits=%d%n",
                    a.level, b.level, newLevel, R1.toString(), R2.toString(), Rprime.toString(), p.bitLength());
        }

        return new Ciphertext(c, Rprime, newLevel);
    }

    // -------------------------
    // Decryption
    // -------------------------
    public static int decrypt(Ciphertext ct, PrivateKey priv) {
        BigInteger p = priv.p;
        BigInteger v = ct.c.mod(p).mod(BigInteger.valueOf(2));

        if (DEBUG) {
            System.out.printf("[DHE.decrypt] level=%d | noise≈%s | decrypted=%s%n",
                    ct.level, ct.noiseBound.toString(), v.toString());
        }

        return v.intValue();
    }

    // -------------------------
    // InternalStore: single-process helper to remember r_i arrays for debugging
    // -------------------------
    private static final class InternalStore {
        private static final java.util.Map<PublicKey, BigInteger[]> map = new java.util.WeakHashMap<>();
        private static final java.util.Map<PublicKey, SecureRandom> rndmap = new java.util.WeakHashMap<>();
        static void store(PublicKey pk, BigInteger[] rvals, SecureRandom rnd) { map.put(pk, rvals); rndmap.put(pk, rnd); }
        static BigInteger[] getR(PublicKey pk) { return map.get(pk); }
    }
}
