package ibe;

import ibe.Ciphertext;
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
 * MIRACL-CORE IBE
 * Test complete Encrypt/Decrypt cycle
 */
public class Main {
    public static void main(String[] args) {

        System.out.println("\n" + "=".repeat(70));
        System.out.println("TESTING COMPLETE ENCRYPT/DECRYPT CYCLE (MIRACL-CORE)");
        System.out.println("=".repeat(70));

        // -------------------------------------------------------------------
        // SETUP
        // -------------------------------------------------------------------
        Object[] result = setup(128);
        Setup.SystemParams params = (Setup.SystemParams) result[0];
        Setup.MasterKey masterKey = (Setup.MasterKey) result[1];

        // Extract private keys
        String bobID = "bob@companyEU.com";
        String aliceID = "alice@companyUS.com";

        Extract.PrivateKey bobKey = extract(bobID, masterKey, params);
        Extract.PrivateKey aliceKey = extract(aliceID, masterKey, params);

        // -------------------------------------------------------------------
        // Test 1: Basic Encrypt / Decrypt
        // -------------------------------------------------------------------
        System.out.println("\n" + "=".repeat(70));
        System.out.println("--- Test 1: Basic Encrypt/Decrypt ---");
        System.out.println("=".repeat(70));

        String message1 = "Hello Bob! This is a secret message.";
        System.out.println("Original message: \"" + message1 + "\"");
        System.out.println("Message length: " + message1.length() + " bytes");
        System.out.println("Message (hex): " + bytesToHex(message1.getBytes()));

        Ciphertext C1 = encrypt(message1, bobID, params);

        System.out.println("\n--- Ciphertext Components ---");
        System.out.println("U (G1 element): " + C1.U.toString());
        System.out.println("V (" + C1.V.length + " bytes): " + bytesToHex(C1.V));
        System.out.println("W (" + C1.W.length + " bytes): " + bytesToHex(C1.W));
        System.out.println("Total ciphertext size: " + C1.toBytes().length + " bytes");

        String decrypted1 = decryptToString(C1, bobKey, params);

        System.out.println("\n--- Decryption Result ---");
        System.out.println("Decrypted message: \"" + decrypted1 + "\"");
        System.out.println("Decrypted (hex): " + bytesToHex(decrypted1.getBytes()));

        boolean test1Pass = message1.equals(decrypted1);
        System.out.println("\n✓ Messages match: " + test1Pass);
        System.out.println("Test 1: " + (test1Pass ? "✓ PASS" : "✗ FAIL"));

        // -------------------------------------------------------------------
        // Test 2: Wrong key (Alice tries to decrypt Bob's ciphertext)
        // -------------------------------------------------------------------
        System.out.println("\n" + "=".repeat(70));
        System.out.println("--- Test 2: Wrong Key (should fail) ---");
        System.out.println("=".repeat(70));

        String wrong = decryptToString(C1, aliceKey, params);
        boolean test2Pass = wrong == null || !wrong.equals(message1);

        System.out.println("Alice decrypts Bob's message: "
                + (wrong == null ? "rejected" : "INCORRECTLY decrypted!"));
        System.out.println("Test 2: " + (test2Pass ? "✓ PASS" : "✗ FAIL"));

        // -------------------------------------------------------------------
        // Test 3: Cross-identity correctness
        // -------------------------------------------------------------------
        System.out.println("\n" + "=".repeat(70));
        System.out.println("--- Test 3: Cross-Identity ---");
        System.out.println("=".repeat(70));

        String msgForAlice = "Secret message tailored for Alice";
        Ciphertext C3 = encrypt(msgForAlice, aliceID, params);

        System.out.println("\nAttempt 1: Alice decrypts (should work)");
        String aliceDecrypt = decryptToString(C3, aliceKey, params);
        System.out.println("Alice's result: " + aliceDecrypt);

        System.out.println("\nAttempt 2: Bob decrypts (should fail)");
        String bobDecrypt = decryptToString(C3, bobKey, params);
        System.out.println("Bob's result: " + (bobDecrypt == null ? "rejected" : bobDecrypt));

        boolean test3Pass =
                msgForAlice.equals(aliceDecrypt) &&
                        (bobDecrypt == null || !msgForAlice.equals(bobDecrypt));

        System.out.println("\nAlice can decrypt: " + msgForAlice.equals(aliceDecrypt));
        System.out.println("Bob cannot decrypt: " + (bobDecrypt == null));
        System.out.println("Test 3: " + (test3Pass ? "✓ PASS" : "✗ FAIL"));

        // -------------------------------------------------------------------
        // Test 4: Multiple encryptions of same message yield unique ciphertexts
        // -------------------------------------------------------------------
        System.out.println("\n" + "=".repeat(70));
        System.out.println("Test 4: Multiple Encryptions Same Message");
        System.out.println("=".repeat(70));

        String message4 = "Test randomization";
        Ciphertext[] ciphertexts = new Ciphertext[5];

        boolean test4Pass = true;
        for (int i = 0; i < 5; i++) {
            ciphertexts[i] = encrypt(message4.getBytes(), bobID, params);
            byte[] dec = decrypt(ciphertexts[i], bobKey, params);
            boolean ok = dec != null && Arrays.equals(dec, message4.getBytes());
            System.out.println("Encryption " + (i + 1) + ": " + (ok ? "✓ OK" : "✗ FAIL"));
            test4Pass &= ok;
        }

        boolean allDifferent = true;
        for (int i = 0; i < 5; i++) {
            for (int j = i + 1; j < 5; j++) {
                if (ciphertexts[i].U.equals(ciphertexts[j].U) &&
                        Arrays.equals(ciphertexts[i].V, ciphertexts[j].V)) {
                    System.out.println("Ciphertexts " + i + " and " + j + " identical!");
                    allDifferent = false;
                }
            }
        }

        System.out.println("All ciphertexts unique: " + allDifferent);
        System.out.println("All decrypt correctly: " + test4Pass);

        test4Pass &= allDifferent;
        System.out.println("Test 4: " + (test4Pass ? "✓ PASS" : "✗ FAIL"));


        // -------------------------------------------------------------------
        // Summary
        // -------------------------------------------------------------------
        System.out.println("\n" + "=".repeat(70));
        System.out.println("TEST SUMMARY");
        System.out.println("=".repeat(70));

        System.out.println("Test 1 - Basic Encrypt/Decrypt:     " + (test1Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 2 - Wrong Key Rejection:       " + (test2Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 3 - Cross-Identity:            " + (test3Pass ? "✓ PASS" : "✗ FAIL"));
        System.out.println("Test 4 - Multiple Enc Same Message: " + (test4Pass ? "✓ PASS" : "✗ FAIL"));

        boolean allPass = test1Pass && test2Pass && test3Pass && test4Pass;

        System.out.println("\n" + "=".repeat(70));
        System.out.println(allPass ? "✓✓✓ ALL TESTS PASSED ✓✓✓" : "✗✗✗ SOME TESTS FAILED ✗✗✗");
        System.out.println("=".repeat(70));
    }
}
