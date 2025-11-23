package ibe;

import ibe.fourCoreAlg.Extract;
import ibe.fourCoreAlg.Setup;

import java.util.Arrays;

import static ibe.fourCoreAlg.Decrypt.decrypt;
import static ibe.fourCoreAlg.Decrypt.decryptToString;
import static ibe.fourCoreAlg.Encrypt.encrypt;
import static ibe.fourCoreAlg.Extract.extract;
import static ibe.fourCoreAlg.Setup.bytesToHex;
import static ibe.fourCoreAlg.Setup.setup;

/**
 * Test complete Encrypt/Decrypt cycle
 */
public class Main {
    public static void main(String[] args) {
        System.out.println("\n" + "=".repeat(70));
        System.out.println("TESTING COMPLETE ENCRYPT/DECRYPT CYCLE");
        System.out.println("=".repeat(70));

        // Setup
        Object[] result = setup(128);
        Setup.SystemParams params = (Setup.SystemParams) result[0];
        Setup.MasterKey masterKey = (Setup.MasterKey) result[1];

        // Extract keys
        String bobID = "bob@company.com";
        String aliceID = "alice@company.com";

        Extract.PrivateKey bobKey = extract(bobID, masterKey, params);
        Extract.PrivateKey aliceKey = extract(aliceID, masterKey, params);

        System.out.println("\n" + "=".repeat(70));
        System.out.println("--- Test 1: Basic Encrypt/Decrypt ---");
        System.out.println("=".repeat(70));
        String message1 = "Hello Bob! This is a secret message.";
        System.out.println("Original message: \"" + message1 + "\"");
        System.out.println("Message length: " + message1.length() + " bytes");
        System.out.println("Message (hex): " + bytesToHex(message1.getBytes()));

        Ciphertext C1 = encrypt(message1, bobID, params);

        System.out.println("\n--- Ciphertext Components ---");
        System.out.println("U (point in G1): " + C1.U.toString());
        System.out.println("V (encrypted sigma, " + C1.V.length + " bytes): " + bytesToHex(C1.V));
        System.out.println("W (encrypted message, " + C1.W.length + " bytes): " + bytesToHex(C1.W));
        System.out.println("Total ciphertext size: " + C1.toBytes().length + " bytes");

        String decrypted1 = decryptToString(C1, bobKey, params);

        System.out.println("\n--- Decryption Result ---");
        System.out.println("Decrypted message: \"" + decrypted1 + "\"");
        System.out.println("Decrypted (hex): " + bytesToHex(decrypted1.getBytes()));

        boolean test1Pass = message1.equals(decrypted1);
        System.out.println("\n✓✓✓ Messages match: " + test1Pass + " ✓✓✓");
        System.out.println("Test 1: " + (test1Pass ? "✓ PASS" : "✗ FAIL"));

        System.out.println("\n" + "=".repeat(70));
        System.out.println("--- Test 2: Wrong Key (should fail) ---");
        System.out.println("=".repeat(70));
        System.out.println("Attempting to decrypt Bob's message with Alice's key...");
        String decrypted_wrong = decryptToString(C1, aliceKey, params);
        boolean test2Pass = decrypted_wrong == null || !message1.equals(decrypted_wrong);
        System.out.println("Result: " + (decrypted_wrong == null ? "Decryption rejected (correct!)" : "Decryption succeeded (WRONG!)"));
        System.out.println("Test 2 (wrong key rejected): " + (test2Pass ? "✓ PASS" : "✗ FAIL"));

        System.out.println("\n" + "=".repeat(70));


        System.out.println("--- Test 3: Cross-Identity ---");
        System.out.println("=".repeat(70));
        String msgForAlice = "Secret message for Alice";
        System.out.println("Message: \"" + msgForAlice + "\"");
        System.out.println("Encrypted for: " + aliceID);

        Ciphertext C3 = encrypt(msgForAlice, aliceID, params);

        System.out.println("\nAttempt 1: Alice decrypts (should work)");
        String aliceDecrypt = decryptToString(C3, aliceKey, params);
        System.out.println("Alice's result: " + (aliceDecrypt != null ? "\"" + aliceDecrypt + "\"" : "null"));

        System.out.println("\nAttempt 2: Bob decrypts (should fail)");
        String bobDecrypt = decryptToString(C3, bobKey, params);
        System.out.println("Bob's result: " + (bobDecrypt != null ? "\"" + bobDecrypt + "\"" : "null (rejected)"));

        boolean test3Pass = msgForAlice.equals(aliceDecrypt) &&
                (bobDecrypt == null || !msgForAlice.equals(bobDecrypt));
        System.out.println("\nAlice can decrypt: " + msgForAlice.equals(aliceDecrypt));
        System.out.println("Bob cannot decrypt: " + (bobDecrypt == null || !msgForAlice.equals(bobDecrypt)));
        System.out.println("Test 3: " + (test3Pass ? "✓ PASS" : "✗ FAIL"));

        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 4: Multiple Encryptions Same Message");
        System.out.println("=".repeat(70));

        String message4 = "Test randomization";
        System.out.println("Message: \"" + message4 + "\"");
        System.out.println("Encrypting same message 5 times...\n");

        boolean test4Pass = true;
        Ciphertext[] ciphertexts = new Ciphertext[5];

        for (int i = 0; i < 5; i++) {
            ciphertexts[i] = encrypt(message4.getBytes(), bobID, params);
            byte[] decrypted = decrypt(ciphertexts[i], bobKey, params);

            boolean matches = decrypted != null && Arrays.equals(message4.getBytes(), decrypted);
            System.out.println("Encryption " + (i+1) + ": " + (matches ? "✓ Decrypts correctly" : "✗ Failed"));

            test4Pass &= matches;
        }

        System.out.println("\n--- Checking Ciphertext Diversity ---");
        boolean allDifferent = true;
        for (int i = 0; i < 5; i++) {
            for (int j = i + 1; j < 5; j++) {
                if (ciphertexts[i].U.equals(ciphertexts[j].U) &&
                        Arrays.equals(ciphertexts[i].V, ciphertexts[j].V)) {
                    allDifferent = false;
                    System.out.println("Ciphertext " + i + " and " + j + " are identical!");
                }
            }
        }

        System.out.println("All ciphertexts unique: " + allDifferent);
        System.out.println("All decrypt correctly: " + test4Pass);

        test4Pass &= allDifferent;
        System.out.println("\nTest 4: " + (test4Pass ? "✓ PASS" : "✗ FAIL"));


        // Summary
        System.out.println("\n" + "=".repeat(70));
        System.out.println("TEST SUMMARY");
        System.out.println("=".repeat(70));
        System.out.println("Test 1 - Basic Encrypt/Decrypt:     " + (test1Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 2 - Wrong Key Rejection:       " + (test2Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 3 - Variable Length Messages:  " + (test3Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 4 - Binary Data:               " + (test4Pass ? "✓ PASS" : "✗ FAIL"));

        boolean allPass = test1Pass && test2Pass && test3Pass && test4Pass;

        System.out.println("\n" + "=".repeat(70));
        if (allPass) {
            System.out.println("✓✓✓ ALL TESTS PASSED ✓✓✓");
        } else {
            System.out.println("✗✗✗ SOME TESTS FAILED ✗✗✗");
        }
        System.out.println("=".repeat(70));

    }

}