package ibe.fourCoreAlg;

import org.miracl.core.BLS12381.*;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Identity-Based Encryption Setup using MIRACL Core BLS12-381
 */
public class Setup {

    // --- MIRACL constants for BLS12-381 ---
    public static final int FIELD_BYTES = 48;               // size of BIG in bytes
    public static final int G1_UNCOMPRESSED_LEN = 1 + FIELD_BYTES * 2; // 0x04 || X || Y
    public static final int FP12_INTS = 12 * BIG.NLEN;     // FP12 elements are 12 BIGs
    public static final int FP12_BYTES = FP12_INTS * 4;    // convert int[] to byte[]

    /* -------------------------
       System Parameters
    ------------------------- */
    public static class SystemParams {
        public ECP P;      // G1 generator
        public ECP2 Q;     // G2 generator
        public ECP P_pub;  // s·P
        public ECP2 Q_pub; // s·Q
        public BIG q;
        public int messageLength = 32;
    }

    /* -------------------------
       Master Secret Key
    ------------------------- */
    public static class MasterKey {
        public BIG s;
    }

    /* -------------------------
       Setup
    ------------------------- */
    public static Object[] setup(int securityParameter) {

        BIG q = new BIG(ROM.CURVE_Order);
        ECP P = ECP.generator();
        ECP2 Q = ECP2.generator();
        BIG s = randomScalar(q);

        ECP P_pub = PAIR.G1mul(P, s);
        ECP2 Q_pub = PAIR.G2mul(Q, s);

        SystemParams params = new SystemParams();
        params.P = P;
        params.Q = Q;
        params.P_pub = P_pub;
        params.Q_pub = Q_pub;
        params.q = q;

        MasterKey masterKey = new MasterKey();
        masterKey.s = s;

        return new Object[]{params, masterKey};
    }

    /* -------------------------
       H1: Hash identity → G1
    ------------------------- */
    public static ECP hashToG1(String identity) {
        // Convert identity string to bytes
        byte[] idBytes = identity.getBytes();

        // Hash bytes to 48-byte array using SHA-256
        byte[] digest = sha256Truncate(idBytes, 48);

        // Convert digest to BIG
        BIG x = BIG.fromBytes(digest);

        // Wrap BIG in FP
        FP fp = new FP(x);

        // Map FP element to G1 using MIRACL's map2point
        ECP P = ECP.map2point(fp);

        // Clear cofactor to ensure P is in the prime-order subgroup
        P.cfp();

        return P;
    }

    /* -------------------------
       H2: Hash GT → byte[]
       Input: FP12 element (GT), output length in bytes
    ------------------------- */
  /* -------------------------
   H2: Hash GT → byte[]
   Input: FP12 element (GT), output length in bytes
------------------------- */
    public static byte[] hashFromGT(FP12 gt, int length) {
        // FP12 has 12 FP elements, each FIELD_BYTES = 48 bytes
        byte[] buf = new byte[12 * FIELD_BYTES];
        gt.toBytes(buf); // writes directly to byte[]

        // Truncate/expand with SHA-256
        return sha256Truncate(buf, length);
    }

    /**
     * H3: Hash (sigma || message) → Z_q
     * Computes r = SHA-256(sigma || message) mod q
     * Ensures r != 0
     */
    public static BIG hashToZq(byte[] sigma, byte[] message, BIG q) {
        // Concatenate sigma || message
        byte[] combined = new byte[sigma.length + message.length];
        System.arraycopy(sigma, 0, combined, 0, sigma.length);
        System.arraycopy(message, 0, combined, sigma.length, message.length);

        // SHA-256
        byte[] digest = sha256(combined);

        // MIRACL BIG expects 48 bytes (BLS12-381 field)
        byte[] scalarBytes = new byte[FIELD_BYTES]; // 48 bytes
        // Copy digest (32 bytes) into lower bytes of 48-byte array
        System.arraycopy(digest, 0, scalarBytes, FIELD_BYTES - digest.length, digest.length);

        BIG r = BIG.fromBytes(scalarBytes); // 48 bytes
        r.mod(q);
        if (r.iszilch()) r.inc(1);

        return r;
    }

    /* -------------------------
       H4: Hash byte[] → byte[]
    ------------------------- */
    public static byte[] hashToBytes(byte[] sigma, int length) {
        return sha256Truncate(sigma, length);
    }

    /* -------------------------
       Utilities
    ------------------------- */
    private static BIG randomScalar(BIG order) {
        SecureRandom sr = new SecureRandom();
        byte[] seed = new byte[FIELD_BYTES]; // 48 bytes for BLS12-381
        BIG r;

        do {
            sr.nextBytes(seed);
            r = BIG.fromBytes(seed);
            r.mod(order);
        } while (r.iszilch());

        return r;
    }

    private static byte[] sha256(byte[] input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return md.digest(input);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] sha256Truncate(byte[] input, int length) {
        byte[] h = sha256(input);
        byte[] out = new byte[length];
        System.arraycopy(h, 0, out, 0, Math.min(length, h.length));
        return out;
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
