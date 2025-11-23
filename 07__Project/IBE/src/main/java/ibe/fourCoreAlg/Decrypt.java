package ibe.fourCoreAlg;

import ibe.Ciphertext;
import org.apache.milagro.amcl.BLS381.*;
import org.apache.milagro.amcl.HASH256;
import java.util.Arrays;

import static ibe.fourCoreAlg.Encrypt.encrypt;
import static ibe.fourCoreAlg.Encrypt.xorBytes;
import static ibe.fourCoreAlg.Extract.extract;
import static ibe.fourCoreAlg.Setup.*;


public class Decrypt {
    /**
     * Decrypt Algorithm
     */
    public static byte[] decrypt(Ciphertext ciphertext, Extract.PrivateKey privateKey, SystemParams params) {
        System.out.println("\n=== Decrypt Algorithm ===");
        System.out.println("Decrypting for: " + privateKey.identity);

        // Check U ∈ G1*
        if (ciphertext.U.is_infinity()) {
            System.out.println("Error: Invalid ciphertext (U is infinity)");
            return null;
        }

        // The key idea: We compute a pairing that depends deterministically on U and d_ID
        //
        // We use: e(Q, d_ID) as our base pairing
        // Then raise it to a power derived from U

        // Base pairing: e(Q, d_ID) = e(Q, s*Q_ID)
        FP12 base_pairing = PAIR.fexp(PAIR.ate(params.Q, privateKey.d_ID));

        // Derive exponent from U deterministically
        byte[] U_bytes = new byte[2 * BIG.MODBYTES + 1];
        ciphertext.U.toBytes(U_bytes, false);

        // Hash U to get a scalar
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

        // Compute: base_pairing^scalar
        FP12 pairing_result = PAIR.GTpow(base_pairing, scalar);

        // Step 1: Recover sigma
        byte[] sigma = xorBytes(ciphertext.V, hashFromGT(pairing_result, params.messageLength));

        // Step 2: Recover message
        byte[] M = xorBytes(ciphertext.W, hashToBytes(sigma, ciphertext.W.length));

        // Step 3: Verification
        BIG r = hashToZq(sigma, M, params.q);
        ECP expected_U = PAIR.G1mul(params.P, r);

        if (!ciphertext.U.equals(expected_U)) {
            System.out.println("Error: Verification failed - ciphertext invalid or tampered");
            return null;
        }

        System.out.println("Decryption successful ✓");
        return M;
    }

    /**
     * Decrypt and return result as String
     * Convenience method for text messages
     */
    public static String decryptToString(Ciphertext ciphertext, Extract.PrivateKey privateKey, SystemParams params) {
        byte[] decrypted = decrypt(ciphertext, privateKey, params);
        if (decrypted == null) {
            return null;
        }
        return new String(decrypted);
    }

    public static void main(String[] args) {
        System.out.println("TESTING DECRYPT ALGORITHM");
        System.out.println("=".repeat(70));

        // Setup
        Object[] result = setup(128);
        SystemParams params = (SystemParams) result[0];
        MasterKey masterKey = (MasterKey) result[1];

        String bobID = "bob@company.com";
        String aliceID = "alice@company.com";

        // Generate private keys
        Extract.PrivateKey bobKey = extract(bobID, masterKey, params);
        Extract.PrivateKey aliceKey = extract(aliceID, masterKey, params);

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 1: Basic Decryption");
        System.out.println("=".repeat(70));

        String message1 = "Hello Bob!";
        System.out.println("Original message: \"" + message1 + "\"");
        System.out.println("Message (hex): " + bytesToHex(message1.getBytes()));
        System.out.println("Encrypting for: " + bobID);

        Ciphertext C1 = encrypt(message1.getBytes(), bobID, params);
        System.out.println("Ciphertext created");
        System.out.println("  U length: " + (2 * BIG.MODBYTES + 1) + " bytes");
        System.out.println("  V length: " + C1.V.length + " bytes");
        System.out.println("  W length: " + C1.W.length + " bytes");

        System.out.println("\nDecrypting with Bob's key...");
        byte[] decrypted1 = decrypt(C1, bobKey, params);

        boolean test1Pass = decrypted1 != null && Arrays.equals(message1.getBytes(), decrypted1);

        if (decrypted1 != null) {
            String decryptedStr = new String(decrypted1);
            System.out.println("\n--- Decryption Result ---");
            System.out.println("Decrypted message: \"" + decryptedStr + "\"");
            System.out.println("Decrypted (hex): " + bytesToHex(decrypted1));
            System.out.println("Messages match: " + test1Pass);
        } else {
            System.out.println("Decryption returned null!");
        }

        System.out.println("\nTest 1: " + (test1Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 2: Wrong Key Rejection");
        System.out.println("=".repeat(70));

        String message2 = "Secret message for Bob";
        System.out.println("Message: \"" + message2 + "\"");
        System.out.println("Encrypting for: " + bobID);

        Ciphertext C2 = encrypt(message2.getBytes(), bobID, params);
        System.out.println("Ciphertext created for Bob");

        System.out.println("\n--- Attempting Decryption with Alice's Key ---");
        System.out.println("This should FAIL (wrong recipient)");
        byte[] wrongDecrypt = decrypt(C2, aliceKey, params);

        boolean test2Pass = (wrongDecrypt == null);

        System.out.println("\n--- Security Check ---");
        System.out.println("Decryption with wrong key failed: " + (wrongDecrypt == null));

        System.out.println("\n--- Attempting Decryption with Bob's Key ---");
        System.out.println("This should SUCCEED (correct recipient)");
        byte[] correctDecrypt = decrypt(C2, bobKey, params);
        boolean bobCanDecrypt = correctDecrypt != null && Arrays.equals(message2.getBytes(), correctDecrypt);

        System.out.println("Bob can decrypt: " + bobCanDecrypt);
        if (bobCanDecrypt) {
            System.out.println("Decrypted: \"" + new String(correctDecrypt) + "\"");
        }

        test2Pass &= bobCanDecrypt;
        System.out.println("\nTest 2: " + (test2Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 3: Tamper Detection - Modified V");
        System.out.println("=".repeat(70));

        String message3 = "Important data";
        System.out.println("Message: \"" + message3 + "\"");

        Ciphertext C3 = encrypt(message3.getBytes(), bobID, params);
        System.out.println("Original ciphertext created");
        System.out.println("V (original): " + bytesToHex(C3.V).substring(0, 40) + "...");

        // Tamper with V (flip one bit)
        Ciphertext C3_tampered = new Ciphertext();
        C3_tampered.U = C3.U;
        C3_tampered.V = Arrays.copyOf(C3.V, C3.V.length);
        C3_tampered.V[0] ^= 0x01; // Flip first bit
        C3_tampered.W = C3.W;
        C3_tampered.recipientIdentity = C3.recipientIdentity;

        System.out.println("V (tampered): " + bytesToHex(C3_tampered.V).substring(0, 40) + "...");

        System.out.println("\n--- Attempting to Decrypt Tampered Ciphertext ---");
        byte[] tamperedResult = decrypt(C3_tampered, bobKey, params);

        boolean test3Pass = (tamperedResult == null);

        System.out.println("\n--- Tamper Detection ---");
        System.out.println("Tampered ciphertext rejected: " + (tamperedResult == null));

        System.out.println("\n--- Verifying Original Still Works ---");
        byte[] originalResult = decrypt(C3, bobKey, params);
        boolean originalWorks = originalResult != null && Arrays.equals(message3.getBytes(), originalResult);
        System.out.println("Original ciphertext still decrypts: " + originalWorks);

        test3Pass &= originalWorks;
        System.out.println("\nTest 3: " + (test3Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 4: Tamper Detection - Modified W");
        System.out.println("=".repeat(70));

        String message4 = "Another test message";
        System.out.println("Message: \"" + message4 + "\"");

        Ciphertext C4 = encrypt(message4.getBytes(), bobID, params);
        System.out.println("Original ciphertext created");
        System.out.println("W (original): " + bytesToHex(C4.W));

        // Tamper with W
        Ciphertext C4_tampered = new Ciphertext();
        C4_tampered.U = C4.U;
        C4_tampered.V = C4.V;
        C4_tampered.W = Arrays.copyOf(C4.W, C4.W.length);
        C4_tampered.W[C4_tampered.W.length - 1] ^= 0xFF; // Flip last byte
        C4_tampered.recipientIdentity = C4.recipientIdentity;

        System.out.println("W (tampered): " + bytesToHex(C4_tampered.W));

        System.out.println("\n--- Attempting to Decrypt Tampered Ciphertext ---");
        byte[] tamperedResult4 = decrypt(C4_tampered, bobKey, params);

        boolean test4Pass = (tamperedResult4 == null);

        System.out.println("\n--- Tamper Detection ---");
        System.out.println("Tampered ciphertext rejected: " + (tamperedResult4 == null));
        System.out.println("Verification equation: U = r*P where r = H3(σ, M)");
        System.out.println("Modified W → Modified M → Different r → U check fails");

        System.out.println("\nTest 4: " + (test4Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 5: Tamper Detection - Modified U");
        System.out.println("=".repeat(70));

        String message5 = "Test U modification";
        System.out.println("Message: \"" + message5 + "\"");

        Ciphertext C5 = encrypt(message5.getBytes(), bobID, params);

        // Create tampered ciphertext with different U
        BIG randomScalar = new BIG(ROM.CURVE_Order);
        randomScalar.shr(1); // Use a different scalar
        ECP modified_U = PAIR.G1mul(params.P, randomScalar);

        Ciphertext C5_tampered = new Ciphertext();
        C5_tampered.U = modified_U;
        C5_tampered.V = C5.V;
        C5_tampered.W = C5.W;
        C5_tampered.recipientIdentity = C5.recipientIdentity;

        System.out.println("U (original): " + C5.U.toString().substring(0, 50) + "...");
        System.out.println("U (tampered): " + C5_tampered.U.toString().substring(0, 50) + "...");

        System.out.println("\n--- Attempting to Decrypt with Modified U ---");
        byte[] tamperedResult5 = decrypt(C5_tampered, bobKey, params);

        boolean test5Pass = (tamperedResult5 == null);

        System.out.println("\n--- Tamper Detection ---");
        System.out.println("Modified U rejected: " + (tamperedResult5 == null));
        System.out.println("Different U → Different pairing mask → Wrong σ → Verification fails");

        System.out.println("\nTest 5: " + (test5Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 6: Invalid Ciphertext - U at Infinity");
        System.out.println("=".repeat(70));

        System.out.println("Creating malformed ciphertext with U = point at infinity");

        Ciphertext C6_invalid = new Ciphertext();
        C6_invalid.U = new ECP(); // Point at infinity
        C6_invalid.V = new byte[32];
        C6_invalid.W = new byte[20];
        C6_invalid.recipientIdentity = bobID;

        System.out.println("U is infinity: " + C6_invalid.U.is_infinity());

        System.out.println("\n--- Attempting to Decrypt Invalid Ciphertext ---");
        byte[] invalidResult = decrypt(C6_invalid, bobKey, params);

        boolean test6Pass = (invalidResult == null);

        System.out.println("\n--- Security Check ---");
        System.out.println("Invalid ciphertext rejected: " + (invalidResult == null));
        System.out.println("Algorithm correctly checks U ∈ G1* (not identity element)");

        System.out.println("\nTest 6: " + (test6Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 7: Edge Cases");
        System.out.println("=".repeat(70));

        boolean test7Pass = true;

        // Empty message
        System.out.println("Testing empty message...");
        byte[] emptyMsg = new byte[0];
        Ciphertext C_empty = encrypt(emptyMsg, bobID, params);
        byte[] decrypted_empty = decrypt(C_empty, bobKey, params);
        boolean emptyWorks = decrypted_empty != null && decrypted_empty.length == 0;
        System.out.println("  Empty message: " + (emptyWorks ? "✓ Success" : "✗ Failed"));
        test7Pass &= emptyWorks;

        // Single byte
        System.out.println("Testing single byte...");
        byte[] singleByte = new byte[]{0x42};
        Ciphertext C_single = encrypt(singleByte, bobID, params);
        byte[] decrypted_single = decrypt(C_single, bobKey, params);
        boolean singleWorks = decrypted_single != null && Arrays.equals(singleByte, decrypted_single);
        System.out.println("  Single byte: " + (singleWorks ? "✓ Success" : "✗ Failed"));
        test7Pass &= singleWorks;

        // All zeros
        System.out.println("Testing all zeros...");
        byte[] zeros = new byte[50];
        Arrays.fill(zeros, (byte) 0x00);
        Ciphertext C_zeros = encrypt(zeros, bobID, params);
        byte[] decrypted_zeros = decrypt(C_zeros, bobKey, params);
        boolean zerosWork = decrypted_zeros != null && Arrays.equals(zeros, decrypted_zeros);
        System.out.println("  All zeros: " + (zerosWork ? "✓ Success" : "✗ Failed"));
        test7Pass &= zerosWork;


        System.out.println("\nTest 7: " + (test7Pass ? "✓ PASS" : "✗ FAIL"));

        // ========================================================================
        // SUMMARY
        // ========================================================================
        System.out.println("\n" + "=".repeat(70));
        System.out.println("DECRYPT ALGORITHM TEST SUMMARY");
        System.out.println("=".repeat(70));
        System.out.println("Test 1  - Basic Decryption:          " + (test1Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 2  - Wrong Key Rejection:       " + (test2Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 3  - Tamper Detection (V):      " + (test3Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 4  - Tamper Detection (W):      " + (test4Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 5  - Tamper Detection (U):      " + (test5Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 6  - Invalid Ciphertext:        " + (test6Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 7 - Edge Cases:                " + (test7Pass ? "✓ PASS" : "✗ FAIL"));

        boolean allPass = test1Pass && test2Pass && test3Pass && test4Pass && test5Pass
                && test6Pass && test7Pass;

        System.out.println("\n" + "=".repeat(70));
        if (allPass) {
            System.out.println("✓✓✓ ALL DECRYPT TESTS PASSED ✓✓✓");
        } else {
            System.out.println("✗✗✗ SOME DECRYPT TESTS FAILED ✗✗✗");
        }
        System.out.println("=".repeat(70));
    }
}
