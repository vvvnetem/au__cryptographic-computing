package ibe.pairing;

import ibe.core.interfaces.PairingScheme;
import java.math.BigInteger;

/**
 * Test JPBC pairing implementation
 */
public class JPBCPairingTest {

    public static void main(String[] args) {
        System.out.println("=== Testing JPBC Pairing Implementation ===\n");

        // Create pairing with test parameters (fast for testing)
        System.out.println("Creating pairing with Type A curve (test parameters)...");
        JPBCPairingScheme pairing = JPBCPairingFactory.createDefaultPairing();
        System.out.println("Pairing created: " + pairing.getName());
        System.out.println("Group order: " + pairing.getGroupOrder());
        System.out.println();

        // Test 1: Basic group operations
        System.out.println("--- Test 1: Group G1 Operations ---");
        testG1Operations(pairing);
        System.out.println();

        // Test 2: Pairing bilinearity
        System.out.println("--- Test 2: Pairing Bilinearity ---");
        testPairingBilinearity(pairing);
        System.out.println();

        // Test 3: Serialization
        System.out.println("--- Test 3: Serialization ---");
        testSerialization(pairing);
        System.out.println();
    }

    private static void testG1Operations(PairingScheme pairing) {
        // Get generator
        PairingScheme.G1Element P = pairing.getG1Generator();
        System.out.println("✓ Generated random element P in G1");

        // Test scalar multiplication
        BigInteger scalar = new BigInteger("12345");
        PairingScheme.G1Element Q = P.multiply(scalar);
        System.out.println("✓ Computed Q = 12345 * P");

        // Test addition
        PairingScheme.G1Element R = P.add(Q);
        System.out.println("✓ Computed R = P + Q");

        // Test identity
        PairingScheme.G1Element identity = pairing.getG1Identity();
        PairingScheme.G1Element shouldBeP = P.add(identity);
        if (shouldBeP.equals(P)) {
            System.out.println("✓ Identity element works correctly: P + 0 = P");
        } else {
            System.out.println("✗ Identity test failed!");
        }

        // Test that P ≠ Q
        if (!P.equals(Q)) {
            System.out.println("✓ P ≠ Q as expected");
        } else {
            System.out.println("✗ Equality test failed!");
        }
    }

    private static void testPairingBilinearity(PairingScheme pairing) {
        // Get elements
        PairingScheme.G1Element P = pairing.getG1Generator();
        PairingScheme.G1Element Q = pairing.getRandomG1Element();

        BigInteger a = new BigInteger("7");
        BigInteger b = new BigInteger("13");

        System.out.println("Testing: e(aP, bQ) = e(P, Q)^(ab)");

        // Left side: e(aP, bQ)
        PairingScheme.G1Element aP = P.multiply(a);
        PairingScheme.G1Element bQ = Q.multiply(b);
        PairingScheme.G2Element left = pairing.pair(aP, bQ);

        // Right side: e(P, Q)^(ab)
        PairingScheme.G2Element ePQ = pairing.pair(P, Q);
        BigInteger ab = a.multiply(b);
        PairingScheme.G2Element right = ePQ.pow(ab);

        if (left.equals(right)) {
            System.out.println("✓ Bilinearity verified: e(aP, bQ) = e(P, Q)^(ab)");
        } else {
            System.out.println("✗ Bilinearity test FAILED!");
        }

        // Additional test: e(P, Q+R) = e(P, Q) * e(P, R)
        System.out.println("\nTesting: e(P, Q+R) = e(P, Q) * e(P, R)");
        PairingScheme.G1Element R = pairing.getRandomG1Element();
        PairingScheme.G1Element QplusR = Q.add(R);

        PairingScheme.G2Element left2 = pairing.pair(P, QplusR);
        PairingScheme.G2Element ePQ2 = pairing.pair(P, Q);
        PairingScheme.G2Element ePR = pairing.pair(P, R);
        PairingScheme.G2Element right2 = ePQ2.multiply(ePR);

        if (left2.equals(right2)) {
            System.out.println("✓ Bilinearity verified: e(P, Q+R) = e(P, Q) * e(P, R)");
        } else {
            System.out.println("✗ Bilinearity test FAILED!");
        }
    }

    private static void testSerialization(PairingScheme pairing) {
        // Create element
        PairingScheme.G1Element P = pairing.getG1Generator();
        System.out.println("Original element P created");

        // Serialize
        byte[] bytes = P.toBytes();
        System.out.println("✓ Serialized to " + bytes.length + " bytes");

        // Deserialize
        PairingScheme.G1Element P2 = pairing.g1FromBytes(bytes);
        System.out.println("✓ Deserialized back to P2");

        // Compare
        if (P.equals(P2)) {
            System.out.println("✓ P = P2 (serialization works correctly)");
        } else {
            System.out.println("✗ Serialization test FAILED!");
        }

        // Test G2 serialization
        PairingScheme.G1Element Q = pairing.getRandomG1Element();
        PairingScheme.G2Element g = pairing.pair(P, Q);
        byte[] gBytes = g.toBytes();
        PairingScheme.G2Element g2 = pairing.g2FromBytes(gBytes);

        if (g.equals(g2)) {
            System.out.println("✓ G2 element serialization works correctly");
        } else {
            System.out.println("✗ G2 serialization test FAILED!");
        }
    }
}