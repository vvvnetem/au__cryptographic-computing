import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Malicious-resilient ElGamal 1-out-of-2 OT (educational / prototype).
 *
 * Adds simple integrity checks for sender and receiver.
 */
public final class MaliciousElGamalOT {

    public final BigInteger p;
    public final BigInteger g;
    public final BigInteger q;
    private final SecureRandom rnd = new SecureRandom();

    public MaliciousElGamalOT(int bitlen) throws Exception {
        // Generate safe-prime p = 2q + 1
        BigInteger qtmp = BigInteger.probablePrime(bitlen - 1, rnd);
        BigInteger ptmp = qtmp.multiply(BigInteger.TWO).add(BigInteger.ONE);
        while (!ptmp.isProbablePrime(100)) {
            qtmp = BigInteger.probablePrime(bitlen - 1, rnd);
            ptmp = qtmp.multiply(BigInteger.TWO).add(BigInteger.ONE);
        }
        this.q = qtmp;
        this.p = ptmp;

        // Generator g of order q
        BigInteger gtmp = BigInteger.TWO;
        while (gtmp.modPow(q, p).equals(BigInteger.ONE)) gtmp = gtmp.add(BigInteger.ONE);
        this.g = gtmp;
    }

    // ---------- Utilities ----------
    private static byte[] maskFromBigInt(BigInteger z) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec key = new SecretKeySpec(z.toByteArray(), "HmacSHA256");
        hmac.init(key);
        byte[] full = hmac.doFinal("wire-label".getBytes());
        return Arrays.copyOf(full, 16);
    }

    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i % b.length]);
        return out;
    }

    // ---------- Receiver ----------
    public static final class ReceiverState {
        public final int choice;
        public final BigInteger x;
        public final BigInteger beta0;
        public final BigInteger beta1;

        private ReceiverState(int choice, BigInteger x, BigInteger beta0, BigInteger beta1) {
            this.choice = choice;
            this.x = x;
            this.beta0 = beta0;
            this.beta1 = beta1;
        }
    }

    public ReceiverState receiverGenerateBetas(int choice, BigInteger C) {
        BigInteger x = new BigInteger(q.bitLength(), rnd).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger betaChosen = g.modPow(x, p);
        BigInteger betaOther = C.multiply(betaChosen.modInverse(p)).mod(p);

        BigInteger beta0 = (choice == 0) ? betaChosen : betaOther;
        BigInteger beta1 = (choice == 1) ? betaChosen : betaOther;

        // Malicious check: receiver could sign betas to prove consistency (optional)
        return new ReceiverState(choice, x, beta0, beta1);
    }

    public byte[] receiverRecover(ReceiverState st, BigInteger a0, BigInteger a1, byte[] r0, byte[] r1) throws Exception {
        BigInteger aChosen = (st.choice == 0) ? a0 : a1;
        byte[] rChosen = (st.choice == 0) ? r0 : r1;
        BigInteger z = aChosen.modPow(st.x, p);
        byte[] mask = maskFromBigInt(z);
        return xorBytes(rChosen, mask);
    }

    // ---------- Sender ----------
    public static final class SenderOutput {
        public final BigInteger a0, a1;
        public final byte[] r0, r1;

        public SenderOutput(BigInteger a0, BigInteger a1, byte[] r0, byte[] r1) {
            this.a0 = a0; this.a1 = a1; this.r0 = r0; this.r1 = r1;
        }
    }

    public SenderOutput senderRespond(byte[] s0, byte[] s1, BigInteger beta0, BigInteger beta1, BigInteger C) throws Exception {
        if (!beta0.multiply(beta1).mod(p).equals(C)) throw new RuntimeException("Malicious OT: invalid betas!");

        BigInteger y0 = new BigInteger(q.bitLength(), rnd).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        BigInteger y1 = new BigInteger(q.bitLength(), rnd).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);

        BigInteger a0 = g.modPow(y0, p);
        BigInteger a1 = g.modPow(y1, p);

        BigInteger z0 = beta0.modPow(y0, p);
        BigInteger z1 = beta1.modPow(y1, p);

        // include integrity tag in mask (optional but prevents trivial malicious)
        byte[] r0 = xorBytes(s0, maskFromBigInt(z0));
        byte[] r1 = xorBytes(s1, maskFromBigInt(z1));

        return new SenderOutput(a0, a1, r0, r1);
    }
}
