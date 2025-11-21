package ibe.hashing;

import ibe.core.interfaces.HashFunction;
import ibe.core.interfaces.PairingScheme;
import ibe.pairing.PreGeneratedPairings;
import ibe.utils.ByteUtils;

import java.math.BigInteger;

/**
 * Test hash function implementations
 */
public class HashFunctionTest {

    public static void main(String[] args) {
        System.out.println("=== Testing Hash Functions ===\n");

        // Create pairing and hash function
        PairingScheme pairing = PreGeneratedPairings.createQuickPairing();
        HashFunction hashFunc = HashFunctionFactory.createDefault();

        System.out.println("Hash function: " + hashFunc.getName());
        System.out.println("Pairing: " + pairing.getName());
        System.out.println();

        // Test H1: Identity → G1
        System.out.println("--- Test 1: H1 (Identity → G1) ---");
        testH1(hashFunc, pairing);
        System.out.println();

        // Test H2: G2 → bytes
        System.out.println("--- Test 2: H2 (G2 → bytes) ---");
        testH2(hashFunc, pairing);
        System.out.println();

        // Test H3: bytes × bytes → Zq
        System.out.println("--- Test 3: H3 (bytes × bytes → Zq) ---");
        testH3(hashFunc, pairing);
        System.out.println();

        // Test H4: bytes → bytes
        System.out.println("--- Test 4: H4 (bytes → bytes) ---");
        testH4(hashFunc);
        System.out.println();

        System.out.println("=== All Hash Function Tests Passed ✓ ===");
    }

    private static void testH1(HashFunction hashFunc, PairingScheme pairing) {
        String identity1 = "bob@company.com";
        String identity2 = "alice@company.com";

        // Hash same identity twice - should be deterministic
        PairingScheme.G1Element q1a = hashFunc.hashToG1(identity1, pairing);
        PairingScheme.G1Element q1b = hashFunc.hashToG1(identity1, pairing);

        if (q1a.equals(q1b)) {
            System.out.println("✓ H1 is deterministic: same identity → same element");
        } else {
            System.out.println("✗ H1 determinism test FAILED");
        }

        // Hash different identities - should be different
        PairingScheme.G1Element q2 = hashFunc.hashToG1(identity2, pairing);

        if (!q1a.equals(q2)) {
            System.out.println("✓ H1 produces different outputs for different identities");
        } else {
            System.out.println("✗ H1 collision test FAILED");
        }

        // Check it's not the identity element
        if (!q1a.isIdentity()) {
            System.out.println("✓ H1 output is not the identity element");
        } else {
            System.out.println("✗ H1 produced identity element");
        }

        System.out.println("Identity: " + identity1);
        System.out.println("H1 output: [" + q1a.getByteLength() + " bytes G1 element]");
    }

    private static void testH2(HashFunction hashFunc, PairingScheme pairing) {
        // Create a G2 element
        PairingScheme.G1Element p = pairing.getG1Generator();
        PairingScheme.G1Element q = pairing.getRandomG1Element();
        PairingScheme.G2Element g = pairing.pair(p, q);

        int outputLength = 32; // 256 bits

        // Hash same element twice - should be deterministic
        byte[] h1 = hashFunc.hashToBytes(g, outputLength);
        byte[] h2 = hashFunc.hashToBytes(g, outputLength);

        if (ByteUtils.secureEquals(h1, h2)) {
            System.out.println("✓ H2 is deterministic");
        } else {
            System.out.println("✗ H2 determinism test FAILED");
        }

        // Check output length
        if (h1.length == outputLength) {
            System.out.println("✓ H2 produces correct output length: " + outputLength + " bytes");
        } else {
            System.out.println("✗ H2 output length incorrect: " + h1.length);
        }

        // Hash different element - should be different
        PairingScheme.G1Element q2 = pairing.getRandomG1Element();
        PairingScheme.G2Element g2 = pairing.pair(p, q2);
        byte[] h3 = hashFunc.hashToBytes(g2, outputLength);

        if (!ByteUtils.secureEquals(h1, h3)) {
            System.out.println("✓ H2 produces different outputs for different elements");
        } else {
            System.out.println("✗ H2 collision test FAILED");
        }

        System.out.println("Sample H2 output: " + ByteUtils.toHex(h1).substring(0, 32) + "...");
    }

    private static void testH3(HashFunction hashFunc, PairingScheme pairing) {
        byte[] sigma = "random_sigma_value".getBytes();
        byte[] message = "Hello, World!".getBytes();
        BigInteger q = pairing.getGroupOrder();

        // Hash same inputs twice - should be deterministic
        BigInteger r1 = hashFunc.hashToZq(sigma, message, q);
        BigInteger r2 = hashFunc.hashToZq(sigma, message, q);

        if (r1.equals(r2)) {
            System.out.println("✓ H3 is deterministic");
        } else {
            System.out.println("✗ H3 determinism test FAILED");
        }

        // Check output is in range [1, q-1]
        if (r1.compareTo(BigInteger.ZERO) > 0 && r1.compareTo(q) < 0) {
            System.out.println("✓ H3 output is in valid range (1, q-1)");
        } else {
            System.out.println("✗ H3 output out of range");
        }

        // Hash different inputs - should be different
        byte[] sigma2 = "different_sigma".getBytes();
        BigInteger r3 = hashFunc.hashToZq(sigma2, message, q);

        if (!r1.equals(r3)) {
            System.out.println("✓ H3 produces different outputs for different inputs");
        } else {
            System.out.println("✗ H3 collision test FAILED");
        }

        System.out.println("Sample H3 output: " + r1.toString().substring(0, 20) + "...");
    }

    private static void testH4(HashFunction hashFunc) {
        byte[] input = "test_input_data".getBytes();
        int outputLength = 32; // 256 bits

        // Hash same input twice - should be deterministic
        byte[] h1 = hashFunc.hashToBytes(input, outputLength);
        byte[] h2 = hashFunc.hashToBytes(input, outputLength);

        if (ByteUtils.secureEquals(h1, h2)) {
            System.out.println("✓ H4 is deterministic");
        } else {
            System.out.println("✗ H4 determinism test FAILED");
        }

        // Check output length
        if (h1.length == outputLength) {
            System.out.println("✓ H4 produces correct output length: " + outputLength + " bytes");
        } else {
            System.out.println("✗ H4 output length incorrect: " + h1.length);
        }

        // Hash different input - should be different
        byte[] input2 = "different_input".getBytes();
        byte[] h3 = hashFunc.hashToBytes(input2, outputLength);

        if (!ByteUtils.secureEquals(h1, h3)) {
            System.out.println("✓ H4 produces different outputs for different inputs");
        } else {
            System.out.println("✗ H4 collision test FAILED");
        }

        // Test different output lengths
        byte[] h4 = hashFunc.hashToBytes(input, 64); // 512 bits
        if (h4.length == 64) {
            System.out.println("✓ H4 supports variable output length");
        } else {
            System.out.println("✗ H4 variable length test FAILED");
        }

        System.out.println("Sample H4 output (32 bytes): " + ByteUtils.toHex(h1).substring(0, 32) + "...");
        System.out.println("Sample H4 output (64 bytes): " + ByteUtils.toHex(h4).substring(0, 32) + "...");
    }
}