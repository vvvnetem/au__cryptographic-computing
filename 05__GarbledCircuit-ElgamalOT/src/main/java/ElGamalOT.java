
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * ElGamal-based 1-out-of-2 Oblivious Transfer helper.
 *
 * Note: This implementation is adapted for educational / prototype use.
 * It provides the receiver and sender helper routines used in the OT flow below.
 */
public final class ElGamalOT {
    public final BigInteger p;
    public final BigInteger g;
    public final BigInteger q;
    private final SecureRandom rnd = new SecureRandom();

    /** Create parameters (safe-prime style). bitlength ~ 512 is used here. */
    public ElGamalOT(int bitlen) {
        // Generate q,p = 2q+1 prime
        BigInteger qtmp = BigInteger.probablePrime(bitlen - 1, rnd);
        BigInteger ptmp = qtmp.multiply(BigInteger.TWO).add(BigInteger.ONE);
        while (!ptmp.isProbablePrime(100)) {
            qtmp = BigInteger.probablePrime(bitlen - 1, rnd);
            ptmp = qtmp.multiply(BigInteger.TWO).add(BigInteger.ONE);
        }
        this.q = qtmp;
        this.p = ptmp;
        // choose generator g of order q
        BigInteger gtmp = BigInteger.TWO;
        while (gtmp.modPow(this.q, this.p).equals(BigInteger.ONE)) {
            gtmp = gtmp.add(BigInteger.ONE);
        }
        this.g = gtmp;
    }

    // ---------- Utilities ----------
    private static byte[] maskFromBigInt(BigInteger z) throws Exception {
        // KDF: SHA-256(z_bytes) -> take first 16 bytes
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] zb = z.toByteArray();
        sha.update(zb);
        byte[] full = sha.digest();
        return Arrays.copyOf(full, 16);
    }

    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i % b.length]);
        return out;
    }

    // ---------- Receiver (Alice) state ----------
    public static final class ReceiverState {
        public final int choice;       // 0 or 1
        public final BigInteger x;    // secret exponent x_i
        public final BigInteger beta0;
        public final BigInteger beta1;

        private ReceiverState(int choice, BigInteger x, BigInteger beta0, BigInteger beta1) {
            this.choice = choice;
            this.x = x;
            this.beta0 = beta0;
            this.beta1 = beta1;
        }
    }

    /**
     * Receiver constructs (beta0,beta1) based on Bob's C and her choice bit.
     * Returns ReceiverState containing (choice,x,beta0,beta1).
     */
    public ReceiverState receiverGenerateBetas(int choice, BigInteger C) {
        // choose random x in [1, q-1]
        BigInteger x = new BigInteger(q.bitLength(), rnd).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger beta_i = g.modPow(x, p);
        // set other beta such that beta0 * beta1 = C (mod p)
        BigInteger beta_other = C.multiply(beta_i.modInverse(p)).mod(p);
        BigInteger beta0, beta1;
        if (choice == 0) {
            beta0 = beta_i; beta1 = beta_other;
        } else {
            beta1 = beta_i; beta0 = beta_other;
        }
        return new ReceiverState(choice, x, beta0, beta1);
    }

    /**
     * Receiver recovers chosen s_i from the sender's message.
     * Inputs: ReceiverState (with x), a0,a1 (BigInteger), r0,r1 (byte[]).
     * Returns recovered s_i (byte[16]).
     */
    public byte[] receiverRecover(ReceiverState st, BigInteger a0, BigInteger a1, byte[] r0, byte[] r1) throws Exception {
        BigInteger ai = (st.choice == 0) ? a0 : a1;
        byte[] ri = (st.choice == 0) ? r0 : r1;
        BigInteger z = ai.modPow(st.x, p); // z_i = a_i^{x_i} mod p
        byte[] mask = maskFromBigInt(z);
        return xorBytes(ri, mask);
    }

    // ---------- Sender (Bob) output ----------
    public static final class SenderOutput {
        public final BigInteger a0, a1;
        public final byte[] r0, r1;
        public SenderOutput(BigInteger a0, BigInteger a1, byte[] r0, byte[] r1) {
            this.a0 = a0; this.a1 = a1; this.r0 = r0; this.r1 = r1;
        }
    }

    /**
     * Sender side: given s0/s1 and (beta0,beta1) from receiver and parameters p,g,
     * compute a0,a1 and r0,r1 to send back. Verifies beta0*beta1 == C first.
     *
     * Inputs:
     *  - s0, s1: messages (byte[16])
     *  - beta0, beta1: received from receiver
     *  - C: chosen by sender earlier
     *
     * Returns (a0,a1,r0,r1).
     */
    public SenderOutput senderRespond(byte[] s0, byte[] s1, BigInteger beta0, BigInteger beta1, BigInteger C) throws Exception {
        // Verify beta0 * beta1 == C (mod p)
        BigInteger lhs = beta0.multiply(beta1).mod(p);
        if (!lhs.equals(C)) throw new RuntimeException("OT sender: beta0 * beta1 != C -> abort (invalid receiver public keys)");

        // choose random y0,y1 in [1,q-1]
        BigInteger y0 = new BigInteger(q.bitLength(), rnd).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger y1 = new BigInteger(q.bitLength(), rnd).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);

        BigInteger a0 = g.modPow(y0, p);
        BigInteger a1 = g.modPow(y1, p);

        BigInteger z0 = beta0.modPow(y0, p);
        BigInteger z1 = beta1.modPow(y1, p);

        byte[] mask0 = maskFromBigInt(z0);
        byte[] mask1 = maskFromBigInt(z1);

        byte[] r0 = xorBytes(s0, mask0);
        byte[] r1 = xorBytes(s1, mask1);

        return new SenderOutput(a0, a1, r0, r1);
    }
}
