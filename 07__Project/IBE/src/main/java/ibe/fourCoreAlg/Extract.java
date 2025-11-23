package ibe.fourCoreAlg;

import org.apache.milagro.amcl.BLS381.*;

import static ibe.fourCoreAlg.Setup.*;

public class Extract {

    /**
     * Extract Algorithm
     * Generates a private key for a given identity
     *
     * @param identity - user identity (e.g., "bob@company.com")
     * @param masterKey - master secret key s
     * @param params - system parameters
     * @return PrivateKey for the given identity
     */
    public static PrivateKey extract(String identity, Setup.MasterKey masterKey, Setup.SystemParams params) {
        System.out.println("\n=== Extract Algorithm ===");
        System.out.println("Generating private key for identity: " + identity);

        // Step 1: Compute Q_ID = H1(ID) ∈ G1*
        // Hash the identity to a point on the elliptic curve
        ECP Q_ID = hashToG1(identity);
        System.out.println("Step 1: Q_ID = H1(ID) computed");
        System.out.println("Q_ID: " + Q_ID.toString());

        // Verify Q_ID is a valid point (not point at infinity)
        if (Q_ID.is_infinity()) {
            throw new RuntimeException("Error: H1 produced point at infinity for identity: " + identity);
        }

        // Step 2: Compute d_ID = s * Q_ID
        // Multiply the point Q_ID by the master secret s
        ECP d_ID = PAIR.G1mul(Q_ID, masterKey.s);
        System.out.println("Step 2: d_ID = s * Q_ID computed");
        System.out.println("d_ID: " + d_ID.toString());

        // Verify d_ID is a valid point
        if (d_ID.is_infinity()) {
            throw new RuntimeException("Error: Private key is point at infinity");
        }

        // Create and return the private key
        PrivateKey privateKey = new PrivateKey();
        privateKey.identity = identity;
        privateKey.d_ID = d_ID;
        privateKey.Q_ID = Q_ID; // Store Q_ID as well for reference

        System.out.println("Extract complete - Private key generated for: " + identity);

        return privateKey;
    }

    /**
     * Private Key class
     * Contains the private decryption key for an identity
     */
    public static class PrivateKey {
        // The identity this key belongs to
        public String identity;

        // The private key point d_ID = s * Q_ID in G1
        public ECP d_ID;

        // The public point Q_ID = H1(ID) in G1 (stored for reference)
        public ECP Q_ID;

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Private Key for: ").append(identity).append("\n");
            sb.append("d_ID: ").append(d_ID.toString()).append("\n");
            sb.append("Q_ID: ").append(Q_ID.toString()).append("\n");
            return sb.toString();
        }

        /**
         * Serialize private key to bytes for storage
         */
        public byte[] toBytes() {
            byte[] bytes = new byte[2 * BIG.MODBYTES + 1];
            d_ID.toBytes(bytes, false); // false = uncompressed format
            return bytes;
        }

        /**
         * Deserialize private key from bytes
         */
        public static PrivateKey fromBytes(byte[] bytes, String identity) {
            ECP d_ID = ECP.fromBytes(bytes);
            PrivateKey key = new PrivateKey();
            key.identity = identity;
            key.d_ID = d_ID;
            key.Q_ID = Setup.hashToG1(identity); // Recompute Q_ID
            return key;
        }
    }

    public static void main(String[] args) {
        System.out.println("Identity-Based Encryption - Setup and Extract Algorithms");
        System.out.println("Using BLS12-381 curve\n");

        // ========== SETUP ==========
        int securityParameter = 128;
        Object[] result = Setup.setup(securityParameter);

        Setup.SystemParams params = (Setup.SystemParams) result[0];
        Setup.MasterKey masterKey = (Setup.MasterKey) result[1];

        // ========== TEST EXTRACT ==========
        System.out.println("\n" + "=".repeat(60));
        System.out.println("TESTING EXTRACT ALGORITHM");
        System.out.println("=".repeat(60));

        // Test 1: Extract key for Bob
        String bobIdentity = "bob@company.com";
        PrivateKey bobKey = extract(bobIdentity, masterKey, params);
        System.out.println("\n" + bobKey.toString());

        // Test 2: Extract key for Alice
        String aliceIdentity = "alice@company.com";
        PrivateKey aliceKey = extract(aliceIdentity, masterKey, params);
        System.out.println("\n" + aliceKey.toString());

        // Test 3: Extract key for Charlie
        String charlieIdentity = "charlie@company.com";
        PrivateKey charlieKey = extract(charlieIdentity, masterKey, params);
        System.out.println("\n" + charlieKey.toString());

        // ========== VERIFY EXTRACT CORRECTNESS ==========
        System.out.println("\n" + "=".repeat(60));
        System.out.println("VERIFYING EXTRACT CORRECTNESS");
        System.out.println("=".repeat(60));

        // Verify: d_ID should equal s * Q_ID
        System.out.println("\n--- Verification 1: d_ID = s * Q_ID ---");
        ECP Q_bob = hashToG1(bobIdentity);
        ECP expected_d_bob = PAIR.G1mul(Q_bob, masterKey.s);
        boolean isCorrect1 = bobKey.d_ID.equals(expected_d_bob);
        System.out.println("Bob's key correctly computed: " + isCorrect1);

        // Verify: Different identities produce different keys
        System.out.println("\n--- Verification 2: Different identities -> Different keys ---");
        boolean keysAreDifferent = !bobKey.d_ID.equals(aliceKey.d_ID) &&
                !bobKey.d_ID.equals(charlieKey.d_ID) &&
                !aliceKey.d_ID.equals(charlieKey.d_ID);
        System.out.println("All keys are unique: " + keysAreDifferent);

        // Verify: Same identity produces same key
        System.out.println("\n--- Verification 3: Same identity -> Same key ---");
        PrivateKey bobKey2 = extract(bobIdentity, masterKey, params);
        boolean sameKeyForSameIdentity = bobKey.d_ID.equals(bobKey2.d_ID);
        System.out.println("Same identity produces same key: " + sameKeyForSameIdentity);

        // ========== TEST PAIRING PROPERTY ==========
        System.out.println("\n" + "=".repeat(60));
        System.out.println("TESTING PAIRING PROPERTY");
        System.out.println("=".repeat(60));

        // The key property: e(d_ID, P) should equal e(Q_ID, P_pub)
        // This is because: d_ID = s*Q_ID, so e(d_ID, P) = e(s*Q_ID, P) = e(Q_ID, P)^s = e(Q_ID, s*P) = e(Q_ID, P_pub)

        System.out.println("\n--- Testing: e(d_ID, P) = e(Q_ID, P_pub) ---");

        ECP2 P2 = ECP2.generator(); // We need a G2 generator for pairing

        // Compute e(d_ID, P2)
        FP12 pairing1 = PAIR.fexp(PAIR.ate(P2, bobKey.d_ID));

        // Compute e(Q_ID, s*P2) - equivalent to e(Q_ID, P2)^s
        ECP2 sP2 = PAIR.G2mul(P2, masterKey.s);
        FP12 pairing2 = PAIR.fexp(PAIR.ate(sP2, bobKey.Q_ID));

        boolean pairingsEqual = pairing1.equals(pairing2);
        System.out.println("e(d_ID, P2) = e(Q_ID, s*P2): " + pairingsEqual);

        if (pairingsEqual) {
            System.out.println("✓ Pairing property verified - Extract algorithm is correct!");
        } else {
            System.out.println("✗ Pairing property failed - there may be an issue!");
        }

        // ========== TEST SERIALIZATION ==========
        System.out.println("\n" + "=".repeat(60));
        System.out.println("TESTING PRIVATE KEY SERIALIZATION");
        System.out.println("=".repeat(60));

        // Serialize Bob's key
        byte[] bobKeyBytes = bobKey.toBytes();
        System.out.println("\nBob's key serialized to " + bobKeyBytes.length + " bytes");
        System.out.println("Serialized key (hex): " + Setup.bytesToHex(bobKeyBytes));

        // Deserialize Bob's key
        PrivateKey bobKeyRestored = PrivateKey.fromBytes(bobKeyBytes, bobIdentity);
        boolean serializationWorks = bobKey.d_ID.equals(bobKeyRestored.d_ID);
        System.out.println("Serialization/Deserialization works: " + serializationWorks);
    }
}
