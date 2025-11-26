package ibe.fourCoreAlg;

import org.miracl.core.BLS12381.*;

import static ibe.fourCoreAlg.Setup.*;

public class Extract {

    /**
     * Extract Algorithm — MIRACL-CORE version
     */
    public static PrivateKey extract(String identity,
                                     MasterKey masterKey,
                                     SystemParams params) {

        System.out.println("\n=== Extract Algorithm ===");
        System.out.println("Generating private key for identity: " + identity);

        // -----------------------------------------------------------
        // Step 1: Q_ID = H1(ID) ∈ G1
        // -----------------------------------------------------------
        ECP Q_ID = hashToG1(identity);
        System.out.println("Step 1: Q_ID = H1(ID) computed");
        System.out.println("Q_ID: " + Q_ID.toString());

        if (Q_ID.is_infinity()) {
            throw new RuntimeException("Error: H1 produced point at infinity for identity: " + identity);
        }

        // -----------------------------------------------------------
        // Step 2: d_ID = s * Q_ID
        // -----------------------------------------------------------
        ECP d_ID = PAIR.G1mul(Q_ID, masterKey.s);
        System.out.println("Step 2: d_ID = s * Q_ID computed");
        System.out.println("d_ID: " + d_ID.toString());

        if (d_ID.is_infinity()) {
            throw new RuntimeException("Error: Private key became point at infinity");
        }

        // Build private key object
        PrivateKey pk = new PrivateKey();
        pk.identity = identity;
        pk.d_ID = d_ID;
        pk.Q_ID = Q_ID;

        System.out.println("Extract complete - Private key generated for: " + identity);
        return pk;
    }

    // ====================================================================
    // Private Key class
    // ====================================================================
    public static class PrivateKey {

        public String identity;
        public ECP d_ID;
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
         * MIRACL-CORE: compressed G1 is always 32 bytes (ECP.AESKEY)
         */
        public byte[] toBytes() {
            // Uncompressed G1: 1 byte prefix + 2 * 48 bytes
            byte[] out = new byte[1 + 2 * Setup.FIELD_BYTES];
            d_ID.toBytes(out, false); // false = uncompressed
            return out;
        }

        public static PrivateKey fromBytes(byte[] bytes, String identity) {
            ECP d_ID = ECP.fromBytes(bytes);
            PrivateKey key = new PrivateKey();
            key.identity = identity;
            key.d_ID = d_ID;
            key.Q_ID = Setup.hashToG1(identity);
            return key;
        }
    }


    // ====================================================================
    // Main test driver (unchanged except for MIRACL APIs)
    // ====================================================================
    public static void main(String[] args) {

        System.out.println("Identity-Based Encryption - Setup and Extract Algorithms");
        System.out.println("Using MIRACL-CORE BLS12-381\n");

        // ========== SETUP ==========
        int securityParameter = 128;
        Object[] result = Setup.setup(securityParameter);

        SystemParams params = (SystemParams) result[0];
        MasterKey masterKey = (MasterKey) result[1];

        // ========== TEST EXTRACT ==========
        System.out.println("\n" + "=".repeat(60));
        System.out.println("TESTING EXTRACT ALGORITHM");
        System.out.println("=".repeat(60));

        String bobIdentity = "bob@company.com";
        PrivateKey bobKey = extract(bobIdentity, masterKey, params);
        System.out.println("\n" + bobKey.toString());

        String aliceIdentity = "alice@company.com";
        PrivateKey aliceKey = extract(aliceIdentity, masterKey, params);
        System.out.println("\n" + aliceKey.toString());

        String charlieIdentity = "charlie@company.com";
        PrivateKey charlieKey = extract(charlieIdentity, masterKey, params);
        System.out.println("\n" + charlieKey.toString());

        // ========== VERIFICATION ==========
        System.out.println("\n" + "=".repeat(60));
        System.out.println("VERIFYING EXTRACT CORRECTNESS");
        System.out.println("=".repeat(60));

        System.out.println("\n--- Verification: d_ID = s * Q_ID ---");
        ECP Q_bob = hashToG1(bobIdentity);
        ECP expected = PAIR.G1mul(Q_bob, masterKey.s);
        boolean ok = bobKey.d_ID.equals(expected);
        System.out.println("Bob's key correct: " + ok);

        System.out.println("\n--- Different IDs give different keys ---");
        boolean diff = !bobKey.d_ID.equals(aliceKey.d_ID)
                && !bobKey.d_ID.equals(charlieKey.d_ID)
                && !aliceKey.d_ID.equals(charlieKey.d_ID);
        System.out.println("Unique keys: " + diff);

        System.out.println("\n--- Same identity gives same key ---");
        PrivateKey bob2 = extract(bobIdentity, masterKey, params);
        boolean same = bobKey.d_ID.equals(bob2.d_ID);
        System.out.println("Same identity yields same key: " + same);

        // ========== PAIRING PROPERTY ==========
        System.out.println("\n" + "=".repeat(60));
        System.out.println("TESTING PAIRING PROPERTY");
        System.out.println("=".repeat(60));

        ECP2 P2 = ECP2.generator();

        FP12 e1 = PAIR.fexp(PAIR.ate(P2, bobKey.d_ID));
        ECP2 sP = PAIR.G2mul(P2, masterKey.s);
        FP12 e2 = PAIR.fexp(PAIR.ate(sP, bobKey.Q_ID));

        boolean pairingOK = e1.equals(e2);
        System.out.println("e(d_ID, P) = e(Q_ID, sP): " + pairingOK);

        // ========== SERIALIZATION ==========
        System.out.println("\n" + "=".repeat(60));
        System.out.println("TESTING PRIVATE KEY SERIALIZATION");
        System.out.println("=".repeat(60));

        byte[] blob = bobKey.toBytes();
        System.out.println("Serialized key length = " + blob.length);

        PrivateKey restored = PrivateKey.fromBytes(blob, bobIdentity);
        boolean serOK = restored.d_ID.equals(bobKey.d_ID);

        System.out.println("Serialization OK: " + serOK);
    }
}
