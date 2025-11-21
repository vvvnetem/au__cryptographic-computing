package ibe.threshold;

import ibe.core.interfaces.SecretSharingScheme;
import ibe.core.interfaces.SecretSharingScheme.Share;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Test class for Shamir Secret Sharing
 */
public class ShamirSecretSharingTest {

    public static void main(String[] args) {
        System.out.println("=== Testing Shamir Secret Sharing ===\n");

        ShamirSecretSharing sss = new ShamirSecretSharing();

        // Use a prime modulus (in real IBE, this will be the group order)
        BigInteger modulus = new BigInteger("340282366920938463463374607431768211297"); // Large prime

        // Test parameters
        int n = 3; // 3 servers
        int t = 2; // Need 2 to reconstruct

        // Secret to share
        BigInteger secret = new BigInteger("123456789");
        System.out.println("Original secret: " + secret);
        System.out.println("Modulus: " + modulus);
        System.out.println("Splitting into n=" + n + " shares with threshold t=" + t + "\n");

        // Split the secret
        List<Share> shares = sss.split(secret, n, t, modulus);

        System.out.println("Generated shares:");
        for (Share share : shares) {
            System.out.printf("  Server %d: share value = %s\n",
                    share.getIndex(), share.getValue());
        }
        System.out.println();

        // Test reconstruction with different combinations
        testReconstruction(sss, shares, List.of(0, 1), secret, modulus, "Servers 1 and 2");
        testReconstruction(sss, shares, List.of(0, 2), secret, modulus, "Servers 1 and 3");
        testReconstruction(sss, shares, List.of(1, 2), secret, modulus, "Servers 2 and 3");
        testReconstruction(sss, shares, List.of(0, 1, 2), secret, modulus, "All servers");

        // Test that single share doesn't reveal secret
        System.out.println("\n=== Testing Security ===");
        System.out.println("With only 1 share (less than threshold), secret cannot be reconstructed");
        System.out.println("Share 1 value: " + shares.get(0).getValue());
        System.out.println("Original secret: " + secret);
        System.out.println("These values should be uncorrelated\n");

    }

    private static void testReconstruction(
            ShamirSecretSharing sss,
            List<Share> allShares,
            List<Integer> indices,
            BigInteger expectedSecret,
            BigInteger modulus,
            String description) {

        // Select subset of shares
        List<Share> subset = new ArrayList<>();
        for (int idx : indices) {
            subset.add(allShares.get(idx));
        }

        // Reconstruct
        BigInteger reconstructed = sss.reconstruct(subset, modulus);

        // Verify
        boolean success = reconstructed.equals(expectedSecret);
        System.out.printf("Test '%s': %s\n",
                description,
                success ? "✓ PASSED" : "✗ FAILED");

        if (!success) {
            System.out.printf("  Expected: %s\n", expectedSecret);
            System.out.printf("  Got: %s\n", reconstructed);
        }
    }
}