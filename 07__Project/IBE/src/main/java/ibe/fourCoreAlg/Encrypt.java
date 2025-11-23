package ibe.fourCoreAlg;

import ibe.Ciphertext;
import org.apache.milagro.amcl.BLS381.*;
import org.apache.milagro.amcl.HASH256;

import java.security.SecureRandom;
import java.util.Arrays;

import static ibe.fourCoreAlg.Setup.*;


public class Encrypt {
    /**
     * Encrypt Algorithm
     * Encrypts a message for a given identity
     *
     * @param message - the message to encrypt (as byte array)
     * @param identity - recipient's identity (e.g., "bob@company.com")
     * @param params - system parameters
     * @return Ciphertext
     */
    public static Ciphertext encrypt(byte[] message, String identity, SystemParams params) {
        System.out.println("\n=== Encrypt Algorithm ===");
        System.out.println("Encrypting for: " + identity);

        // Step 1: Compute Q_ID = H1(ID)
        ECP Q_ID = hashToG1(identity);

        // Step 2: Choose random σ
        byte[] sigma = new byte[params.messageLength];
        new SecureRandom().nextBytes(sigma);

        // Step 3: Set r = H3(σ, M)
        BIG r = hashToZq(sigma, message, params.q);

        // Step 4: Compute U = r*P
        ECP U = PAIR.G1mul(params.P, r);

        // Step 5: Compute the pairing mask (has to match with decryption)
        // We compute: e(Q, s*Q_ID)^hash(U)
        // e(s*Q, Q_ID)^hash(U) = e(Q_pub, Q_ID)^hash(U)

        FP12 base_pairing = PAIR.fexp(PAIR.ate(params.Q_pub, Q_ID)); // e(s*Q, Q_ID)

        // Hash U to get same scalar as in decryption
        byte[] U_bytes = new byte[2 * BIG.MODBYTES + 1];
        U.toBytes(U_bytes, false);

        HASH256 sha = new HASH256();
        sha.process_array(U_bytes);
        byte[] hash = sha.hash();

        byte[] scalarBytes = new byte[BIG.MODBYTES];
        System.arraycopy(hash, 0, scalarBytes, 0, Math.min(hash.length, BIG.MODBYTES));
        BIG scalar = BIG.fromBytes(scalarBytes);
        scalar.mod(params.q);

        if (scalar.iszilch()) {
            scalar.inc(1);
        }

        FP12 pairing_result = PAIR.GTpow(base_pairing, scalar);

        // Step 6: Compute V = σ ⊕ H2(pairing_result)
        byte[] V = xorBytes(sigma, hashFromGT(pairing_result, params.messageLength));

        // Step 7: Compute W = M ⊕ H4(σ)
        byte[] W = xorBytes(message, hashToBytes(sigma, message.length));

        Ciphertext C = new Ciphertext();
        C.U = U;
        C.V = V;
        C.W = W;
        C.recipientIdentity = identity;

        System.out.println("Encryption complete");
        return C;
    }



    /**
     * XOR two byte arrays
     */
    static byte[] xorBytes(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("Arrays must have same length for XOR");
        }

        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    /**
     * Overloaded encrypt method that takes a String message
     */
    public static Ciphertext encrypt(String message, String identity, SystemParams params) {
        return encrypt(message.getBytes(), identity, params);
    }


    public static void main(String[] args) {
        System.out.println("\n" + "=".repeat(70));
        System.out.println("TESTING ENCRYPT ALGORITHM");
        System.out.println("=".repeat(70));

        // Setup
        Object[] result = setup(128);
        SystemParams params = (SystemParams) result[0];
        MasterKey masterKey = (MasterKey) result[1];

        String bobID = "bob@company.com";
        String aliceID = "alice@company.com";

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 1: Basic Encryption");
        System.out.println("=".repeat(70));

        String message1 = "Hello World!";
        System.out.println("Message: \"" + message1 + "\"");
        System.out.println("Message length: " + message1.length() + " bytes");
        System.out.println("Message (hex): " + bytesToHex(message1.getBytes()));
        System.out.println("Recipient: " + bobID);

        Ciphertext C1 = encrypt(message1.getBytes(), bobID, params);

        System.out.println("\n--- Ciphertext Structure ---");
        System.out.println("U (r*P in G1):");
        System.out.println("  " + C1.U.toString());
        System.out.println("  Is valid point: " + !C1.U.is_infinity());

        System.out.println("\nV (σ ⊕ H2(pairing)):");
        System.out.println("  Length: " + C1.V.length + " bytes");
        System.out.println("  Hex: " + bytesToHex(C1.V));

        System.out.println("\nW (M ⊕ H4(σ)):");
        System.out.println("  Length: " + C1.W.length + " bytes");
        System.out.println("  Hex: " + bytesToHex(C1.W));

        System.out.println("\n--- Ciphertext Properties ---");
        int ciphertextSize = C1.toBytes().length;
        int messageSize = message1.getBytes().length;
        int overhead = ciphertextSize - messageSize;
        double expansionRatio = (double) ciphertextSize / messageSize;

        System.out.println("Message size: " + messageSize + " bytes");
        System.out.println("Ciphertext size: " + ciphertextSize + " bytes");
        System.out.println("Overhead: " + overhead + " bytes");
        System.out.println("Expansion ratio: " + String.format("%.2f", expansionRatio) + "x");

        boolean test1Pass = C1.U != null && C1.V != null && C1.W != null && !C1.U.is_infinity();
        System.out.println("\nTest 1: " + (test1Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 2: Randomized Encryption (Same Message Twice)");
        System.out.println("=".repeat(70));

        String message2 = "Same message";
        System.out.println("Message: \"" + message2 + "\"");
        System.out.println("Encrypting twice for: " + bobID);

        Ciphertext C2a = encrypt(message2.getBytes(), bobID, params);
        Ciphertext C2b = encrypt(message2.getBytes(), bobID, params);

        System.out.println("\n--- First Encryption ---");
        String u2a_str = C2a.U.toString();
        String v2a_hex = bytesToHex(C2a.V);
        String w2a_hex = bytesToHex(C2a.W);
        System.out.println("U: " + (u2a_str.length() > 60 ? u2a_str.substring(0, 60) + "..." : u2a_str));
        System.out.println("V: " + (v2a_hex.length() > 40 ? v2a_hex.substring(0, 40) + "..." : v2a_hex));
        System.out.println("W: " + (w2a_hex.length() > 40 ? w2a_hex.substring(0, 40) + "..." : w2a_hex));

        System.out.println("\n--- Second Encryption ---");
        String u2b_str = C2b.U.toString();
        String v2b_hex = bytesToHex(C2b.V);
        String w2b_hex = bytesToHex(C2b.W);
        System.out.println("U: " + (u2b_str.length() > 60 ? u2b_str.substring(0, 60) + "..." : u2b_str));
        System.out.println("V: " + (v2b_hex.length() > 40 ? v2b_hex.substring(0, 40) + "..." : v2b_hex));
        System.out.println("W: " + (w2b_hex.length() > 40 ? w2b_hex.substring(0, 40) + "..." : w2b_hex));

        boolean u_different = !C2a.U.equals(C2b.U);
        boolean v_different = !Arrays.equals(C2a.V, C2b.V);
        boolean w_different = !Arrays.equals(C2a.W, C2b.W);

        System.out.println("\n--- Randomization Check ---");
        System.out.println("U components different: " + u_different);
        System.out.println("V components different: " + v_different);
        System.out.println("W components different: " + w_different);

        boolean test2Pass = u_different && v_different && w_different;
        System.out.println("\nRandomization working: " + test2Pass + " (prevents identical ciphertexts)");
        System.out.println("Test 2: " + (test2Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 3: Different Recipients");
        System.out.println("=".repeat(70));

        String message3 = "Shared message";
        System.out.println("Message: \"" + message3 + "\"");
        System.out.println("Encrypting for Bob and Alice...");

        Ciphertext C3_bob = encrypt(message3.getBytes(), bobID, params);
        Ciphertext C3_alice = encrypt(message3.getBytes(), aliceID, params);


        System.out.println("\n--- Bob's Ciphertext ---");
        System.out.println("Recipient: " + bobID);
        String U_bob = C3_bob.U.toString();
        String V_bob = bytesToHex(C3_bob.V);
        String W_bob = bytesToHex(C3_bob.W);

        System.out.println("U: " + (U_bob.length() > 60 ? U_bob.substring(0, 60) + "..." : U_bob));
        System.out.println("V: " + (V_bob.length() > 40 ? V_bob.substring(0, 40) + "..." : V_bob));
        System.out.println("W: " + (W_bob.length() > 40 ? W_bob.substring(0, 40) + "..." : W_bob));


        System.out.println("\n--- Alice's Ciphertext ---");
        System.out.println("Recipient: " + aliceID);
        String U_alice = C3_alice.U.toString();
        String V_alice = bytesToHex(C3_alice.V);
        String W_alice = bytesToHex(C3_alice.W);
        System.out.println("U: " + (U_alice.length() > 60 ? U_alice.substring(0, 60) + "..." : U_alice));
        System.out.println("V: " + (V_alice.length() > 40 ? V_alice.substring(0, 40) + "..." : V_alice));
        System.out.println("W: " + (W_alice.length() > 40 ? W_alice.substring(0, 40) + "..." : W_alice));

        boolean different_recipients = !C3_bob.U.equals(C3_alice.U) ||
                !Arrays.equals(C3_bob.V, C3_alice.V)
                || !Arrays.equals(C3_bob.W, C3_alice.W);

        System.out.println("\n--- Identity-Specific Encryption ---");
        System.out.println("Ciphertexts are different: " + different_recipients);
        System.out.println("(Each recipient gets unique ciphertext)");

        boolean test3Pass = different_recipients;
        System.out.println("\nTest 3: " + (test3Pass ? "✓ PASS" : "✗ FAIL"));



        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 4: Verify Pairing Computation");
        System.out.println("=".repeat(70));

        String message4 = "Pairing test";
        System.out.println("Message: \"" + message4 + "\"");

        // Manually trace through encryption
        ECP Q_ID = hashToG1(bobID);
        String qid_str = Q_ID.toString();
        System.out.println("\nQ_ID = H1(bobID):");
        System.out.println("  " + (qid_str.length() > 60 ? qid_str.substring(0, 60) + "..." : qid_str));

        Ciphertext C4 = encrypt(message4.getBytes(), bobID, params);

        String u4_str = C4.U.toString();
        System.out.println("\nU = r*P:");
        System.out.println("  " + (u4_str.length() > 60 ? u4_str.substring(0, 60) + "..." : u4_str));

        // Verify pairing can be computed
        FP12 g_ID = PAIR.fexp(PAIR.ate(params.Q_pub, Q_ID));
        System.out.println("\ng_ID = e(Q_pub, Q_ID) computed successfully");
        System.out.println("g_ID is not identity: " + !g_ID.isunity());

        // Hash U for scalar
        byte[] U_bytes = new byte[2 * BIG.MODBYTES + 1];
        C4.U.toBytes(U_bytes, false);
        HASH256 sha = new HASH256();
        sha.process_array(U_bytes);
        byte[] hash = sha.hash();
        byte[] scalarBytes = new byte[BIG.MODBYTES];
        System.arraycopy(hash, 0, scalarBytes, 0, Math.min(hash.length, BIG.MODBYTES));
        BIG scalar = BIG.fromBytes(scalarBytes);
        scalar.mod(params.q);
        if (scalar.iszilch()) scalar.inc(1);

        System.out.println("scalar = hash(U) computed");
        System.out.println("scalar is non-zero: " + !scalar.iszilch());

        FP12 pairing_result = PAIR.GTpow(g_ID, scalar);
        System.out.println("pairing^scalar computed successfully");

        boolean test4Pass = !g_ID.isunity() && !scalar.iszilch();
        System.out.println("\nTest 4: " + (test4Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test : Empty and Edge Case Messages");
        System.out.println("=".repeat(70));

        boolean test5Pass = true;

        // Test empty message
        System.out.println("Testing empty message...");
        try {
            byte[] emptyMsg = new byte[0];
            Ciphertext C_empty = encrypt(emptyMsg, bobID, params);
            System.out.println("  Empty message: ✓ Encrypted (W length = " + C_empty.W.length + ")");
            test5Pass &= (C_empty.W.length == 0);
        } catch (Exception e) {
            System.out.println("  Empty message: ✗ Failed - " + e.getMessage());
            test5Pass = false;
        }

        // Test single byte
        System.out.println("Testing single byte message...");
        try {
            byte[] singleByte = new byte[]{0x42};
            Ciphertext C_single = encrypt(singleByte, bobID, params);
            System.out.println("  Single byte: ✓ Encrypted (W length = " + C_single.W.length + ")");
            test5Pass &= (C_single.W.length == 1);
        } catch (Exception e) {
            System.out.println("  Single byte: ✗ Failed - " + e.getMessage());
            test5Pass = false;
        }

        // Test all zeros
        System.out.println("Testing all-zero message...");
        try {
            byte[] zeros = new byte[64];
            Arrays.fill(zeros, (byte) 0x00);
            Ciphertext C_zeros = encrypt(zeros, bobID, params);
            System.out.println("  All zeros: ✓ Encrypted");
            System.out.println("  W is not all zeros: " + !Arrays.equals(C_zeros.W, zeros));
            test5Pass &= !Arrays.equals(C_zeros.W, zeros);
        } catch (Exception e) {
            System.out.println("  All zeros: ✗ Failed - " + e.getMessage());
            test5Pass = false;
        }

        System.out.println("\nTest 5: " + (test5Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        // SUMMARY
        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("ENCRYPT ALGORITHM TEST SUMMARY");
        System.out.println("=".repeat(70));
        System.out.println("Test 1 - Basic Encryption:          " + (test1Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 2 - Randomization:              " + (test2Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 3 - Different Recipients:       " + (test3Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 4 - Pairing Computation:        " + (test4Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 5 - Edge Cases:                 " + (test5Pass ? "✓ PASS" : "✗ FAIL"));

        boolean allPass = test1Pass && test2Pass && test3Pass && test4Pass && test5Pass;

        System.out.println("\n" + "=".repeat(70));
        if (allPass) {
            System.out.println("✓✓✓ ALL ENCRYPT TESTS PASSED ✓✓✓");
        } else {
            System.out.println("✗✗✗ SOME ENCRYPT TESTS FAILED ✗✗✗");
        }
        System.out.println("=".repeat(70));

    }
}
