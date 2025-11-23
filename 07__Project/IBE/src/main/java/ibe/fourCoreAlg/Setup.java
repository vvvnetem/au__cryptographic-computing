package ibe.fourCoreAlg;

import org.apache.milagro.amcl.BLS381.*;
import org.apache.milagro.amcl.RAND;
import org.apache.milagro.amcl.HASH256;
import org.apache.milagro.amcl.HASH512;
import java.security.SecureRandom;

/**
 * Identity-Based Encryption Setup using BLS12-381 curve
 */
public class Setup {

    /**
     * System Parameters
     */
    public static class SystemParams {
        // Generator point P in G1
        public ECP P;

        // Generator point Q in G2
        public ECP2 Q;

        // Master public key in G1: P_pub = s*P
        public ECP P_pub;

        // Master public key in G2: Q_pub = s*Q (needed for encryption)
        public ECP2 Q_pub;

        // Order of the groups
        public BIG q;

        // Message length in bytes
        public int messageLength = 32;

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("System Parameters (BLS12-381):\n");
            sb.append("P (G1 generator): ").append(P.toString()).append("\n");
            sb.append("Q (G2 generator): ").append(Q.toString()).append("\n");
            sb.append("P_pub (s*P in G1): ").append(P_pub.toString()).append("\n");
            sb.append("Q_pub (s*Q in G2): ").append(Q_pub.toString()).append("\n");
            sb.append("q (Group Order): ").append(q.toString()).append("\n");
            return sb.toString();
        }
    }

    /**
     * Master Key - Private (kept secret by PKG)
     */
    public static class MasterKey {
        // Master secret s in Zq*
        public BIG s;

        @Override
        public String toString() {
            return "Master Key: " + s.toString();
        }
    }

    /**
     * Setup Algorithm - Adapted for BLS12-381
     */
    public static Object[] setup(int securityParameter) {
        System.out.println("=== IBE Setup Algorithm (BLS12-381) ===");
        System.out.println("Security Parameter: " + securityParameter);

        // Step 1: Get group order
        BIG q = new BIG(ROM.CURVE_Order);
        System.out.println("\nGroup order q: " + q.toString());

        // Step 2: Get generators for G1 and G2
        ECP P = ECP.generator();      // G1 generator
        ECP2 Q = ECP2.generator();    // G2 generator
        System.out.println("Generators P (G1) and Q (G2) chosen");

        // Step 3: Generate master secret s
        RAND rng = createRNG();
        BIG s = BIG.randomnum(q, rng);
        while (s.iszilch()) {
            s = BIG.randomnum(q, rng);
        }
        System.out.println("Master secret s generated");

        // Step 4: Compute public keys in both groups
        ECP P_pub = PAIR.G1mul(P, s);     // s*P in G1
        ECP2 Q_pub = PAIR.G2mul(Q, s);    // s*Q in G2
        System.out.println("Master public keys computed in G1 and G2");

        // Create system parameters
        SystemParams params = new SystemParams();
        params.P = P;
        params.Q = Q;
        params.P_pub = P_pub;
        params.Q_pub = Q_pub;
        params.q = q;

        // Create master key
        MasterKey masterKey = new MasterKey();
        masterKey.s = s;

        System.out.println("\n=== Setup Complete ===");
        System.out.println(params.toString());

        return new Object[]{params, masterKey};
    }

    /**
     * H1: Hash function from identity string to point in G1
     * Maps {0,1}* -> G1*
     *
     * @param identity - user identity (e.g., email address)
     * @return point Q_ID in G1
     */
    public static ECP hashToG1(String identity) {
        // Use a proper hash-to-curve approach
        // We'll use the "try-and-increment" method with proper byte handling

        byte[] idBytes = identity.getBytes();
        int counter = 0;
        int maxAttempts = 256;

        while (counter < maxAttempts) {
            // Create hash input: identity || counter
            HASH256 sha = new HASH256();
            sha.process_array(idBytes);
            sha.process_num(counter);
            byte[] hash = sha.hash();

            // Convert hash to BIG (need to ensure proper size)
            // BLS381 BIG needs BIG.MODBYTES bytes
            byte[] bigBytes = new byte[BIG.MODBYTES];

            // Copy hash into bigBytes, padding with zeros if needed
            int copyLen = Math.min(hash.length, BIG.MODBYTES);
            System.arraycopy(hash, 0, bigBytes, 0, copyLen);

            // Create BIG from bytes
            BIG x = BIG.fromBytes(bigBytes);

            // Reduce modulo the field prime
            BIG modulus = new BIG(ROM.Modulus);
            x.mod(modulus);

            // Try to create a point with this x-coordinate
            ECP point = new ECP(x);

            // Check if we got a valid point (not point at infinity)
            if (!point.is_infinity()) {
                return point;
            }

            counter++;
        }

        // Fallback: if we couldn't find a point, use the generator multiplied by hash
        // This is less ideal but ensures we always return a valid point
        HASH256 sha = new HASH256();
        sha.process_array(idBytes);
        byte[] hash = sha.hash();

        byte[] bigBytes = new byte[BIG.MODBYTES];
        int copyLen = Math.min(hash.length, BIG.MODBYTES);
        System.arraycopy(hash, 0, bigBytes, 0, copyLen);

        BIG scalar = BIG.fromBytes(bigBytes);
        BIG order = new BIG(ROM.CURVE_Order);
        scalar.mod(order);

        if (scalar.iszilch()) {
            scalar.inc(1);
        }

        return PAIR.G1mul(ECP.generator(), scalar);
    }

    /**
     * H2: Hash function from GT element to byte array
     * Maps GT -> {0,1}^n
     *
     * @param element - element in GT (FP12)
     * @param length - desired output length in bytes
     * @return byte array of specified length
     */
    public static byte[] hashFromGT(FP12 element, int length) {
        // Convert FP12 to bytes
        byte[] elementBytes = new byte[12 * BIG.MODBYTES];
        element.toBytes(elementBytes);

        // Hash using SHA-256 or SHA-512
        if (length <= 32) {
            HASH256 sha = new HASH256();
            sha.process_array(elementBytes);
            byte[] hash = sha.hash();

            if (length == hash.length) {
                return hash;
            }

            byte[] result = new byte[length];
            System.arraycopy(hash, 0, result, 0, Math.min(length, hash.length));
            return result;
        } else {
            HASH512 sha = new HASH512();
            sha.process_array(elementBytes);
            byte[] hash = sha.hash();

            if (length <= hash.length) {
                byte[] result = new byte[length];
                System.arraycopy(hash, 0, result, 0, length);
                return result;
            } else {
                // For longer outputs, use multiple rounds
                byte[] result = new byte[length];
                int offset = 0;
                int round = 0;

                while (offset < length) {
                    HASH512 sha2 = new HASH512();
                    sha2.process_array(elementBytes);
                    sha2.process_num(round);
                    byte[] roundHash = sha2.hash();

                    int copyLen = Math.min(roundHash.length, length - offset);
                    System.arraycopy(roundHash, 0, result, offset, copyLen);
                    offset += copyLen;
                    round++;
                }

                return result;
            }
        }
    }

    /**
     * H3: Hash function from two byte arrays to Zq*
     * Maps {0,1}^n x {0,1}^n -> Zq*
     *
     * @param sigma - random value
     * @param message - message bytes
     * @param q - group order
     * @return element r in Zq*
     */
    public static BIG hashToZq(byte[] sigma, byte[] message, BIG q) {
        // Concatenate inputs
        byte[] combined = new byte[sigma.length + message.length];
        System.arraycopy(sigma, 0, combined, 0, sigma.length);
        System.arraycopy(message, 0, combined, sigma.length, message.length);

        // Hash using SHA-256
        HASH256 sha = new HASH256();
        sha.process_array(combined);
        byte[] hash = sha.hash();

        // Convert to BIG with proper size
        byte[] bigBytes = new byte[BIG.MODBYTES];
        int copyLen = Math.min(hash.length, BIG.MODBYTES);
        System.arraycopy(hash, 0, bigBytes, 0, copyLen);

        BIG r = BIG.fromBytes(bigBytes);
        r.mod(q);

        // Ensure r is not zero
        if (r.iszilch()) {
            r.inc(1);
        }

        return r;
    }

    /**
     * H4: Hash function from byte array to byte array
     * Maps {0,1}^n -> {0,1}^n
     *
     * @param sigma - input bytes
     * @param length - desired output length
     * @return output bytes
     */
    public static byte[] hashToBytes(byte[] sigma, int length) {
        if (length <= 32) {
            HASH256 sha = new HASH256();
            sha.process_array(sigma);
            byte[] hash = sha.hash();

            if (length == hash.length) {
                return hash;
            }

            byte[] result = new byte[length];
            System.arraycopy(hash, 0, result, 0, Math.min(length, hash.length));
            return result;
        } else if (length <= 64) {
            HASH512 sha = new HASH512();
            sha.process_array(sigma);
            byte[] hash = sha.hash();

            if (length <= hash.length) {
                byte[] result = new byte[length];
                System.arraycopy(hash, 0, result, 0, length);
                return result;
            }
        }

        // For longer outputs, use multiple rounds
        byte[] result = new byte[length];
        int offset = 0;
        int round = 0;

        while (offset < length) {
            HASH256 sha = new HASH256();
            sha.process_array(sigma);
            sha.process_num(round);
            byte[] roundHash = sha.hash();

            int copyLen = Math.min(roundHash.length, length - offset);
            System.arraycopy(roundHash, 0, result, offset, copyLen);
            offset += copyLen;
            round++;
        }

        return result;
    }

    /**
     * Create a cryptographically secure random number generator
     *
     * @return RAND object seeded with secure random data
     */
    private static RAND createRNG() {
        RAND rng = new RAND();

        // Seed with secure random data
        SecureRandom secureRandom = new SecureRandom();
        byte[] seed = new byte[128];
        secureRandom.nextBytes(seed);
        rng.clean();
        rng.seed(seed.length, seed);

        return rng;
    }

    /**
     * Helper method to convert bytes to hex string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Main method for testing
     */
    public static void main(String[] args) {
        System.out.println("Identity-Based Encryption - Setup Algorithm");
        System.out.println("Using BLS12-381 curve\n");

        // Run setup with security parameter
        int securityParameter = 128;
        Object[] result = setup(securityParameter);

        SystemParams params = (SystemParams) result[0];
        MasterKey masterKey = (MasterKey) result[1];

        System.out.println("\n=== Testing Hash Functions ===");

        // Test H1: Hash to G1
        System.out.println("\n--- Testing H1: Hash to G1 ---");
        String testIdentity = "bob@company.com";
        ECP Q_ID = hashToG1(testIdentity);
        System.out.println("H1('" + testIdentity + "'):");
        System.out.println("Mapped to G1 point: " + Q_ID.toString());
        System.out.println("Is valid point: " + !Q_ID.is_infinity());

        // Test with another identity
        String testIdentity2 = "alice@company.com";
        ECP Q_ID2 = hashToG1(testIdentity2);
        System.out.println("\nH1('" + testIdentity2 + "'):");
        System.out.println("Mapped to G1 point: " + Q_ID2.toString());
        System.out.println("Is valid point: " + !Q_ID2.is_infinity());

        // Test H2: Hash from GT
        System.out.println("\n--- Testing H2: Hash from GT ---");
        ECP2 Q2gen = ECP2.generator();
        FP12 testGT = PAIR.fexp(PAIR.ate(Q2gen, Q_ID));
        byte[] h2Result = hashFromGT(testGT, 32);
        System.out.println("H2(GT element):");
        System.out.println("Output (32 bytes, hex): " + bytesToHex(h2Result));

        // Test H3: Hash to Zq
        System.out.println("\n--- Testing H3: Hash to Zq ---");
        byte[] testSigma = "random_sigma_value_12345".getBytes();
        byte[] testMessage = "Hello World".getBytes();
        BIG h3Result = hashToZq(testSigma, testMessage, params.q);
        System.out.println("H3(sigma, message):");
        System.out.println("Output in Zq: " + h3Result.toString());

        BIG zero = new BIG(0);
        boolean isNonZero = BIG.comp(h3Result, zero) > 0;
        boolean isLessThanQ = BIG.comp(h3Result, params.q) < 0;
        System.out.println("Is in range [1, q): " + (isNonZero && isLessThanQ));

        // Test H4: Hash to bytes
        System.out.println("\n--- Testing H4: Hash to bytes ---");
        byte[] h4Result = hashToBytes(testSigma, 32);
        System.out.println("H4(sigma):");
        System.out.println("Output (32 bytes, hex): " + bytesToHex(h4Result));

        // Verify pairing works
        System.out.println("\n=== Testing Pairing Operation ===");
        ECP2 Q2 = ECP2.generator();
        FP12 pairing = PAIR.fexp(PAIR.ate(Q2, params.P));
        System.out.println("e(P, Q2) computed successfully");
        String pairingStr = pairing.toString();
        if (pairingStr.length() > 100) {
            System.out.println("Pairing result: " + pairingStr.substring(0, 100) + "...");
        } else {
            System.out.println("Pairing result: " + pairingStr);
        }

        // Test bilinearity: e(aP, bQ) = e(P, Q)^(ab)
        System.out.println("\n=== Testing Bilinearity ===");
        BIG a = new BIG(5);
        BIG b = new BIG(7);
        ECP aP = PAIR.G1mul(params.P, a);
        ECP2 bQ = PAIR.G2mul(Q2, b);

        FP12 lhs = PAIR.fexp(PAIR.ate(bQ, aP)); // e(aP, bQ)
        FP12 rhs = PAIR.fexp(PAIR.ate(Q2, params.P)); // e(P, Q)

        // Convert DBIG to BIG
        DBIG ab_dbig = BIG.mul(a, b);
        BIG ab = new BIG(ab_dbig);
        ab.mod(params.q);
        rhs = PAIR.GTpow(rhs, ab);

        System.out.println("e(5P, 7Q) computed");
        System.out.println("e(P, Q)^35 computed");
        System.out.println("Are they equal? " + lhs.equals(rhs));

        System.out.println("\n=== Setup and Tests Complete ===");
    }
}