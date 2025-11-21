package ibe.threshold;

import ibe.core.interfaces.SecretSharingScheme;

/**
 * Test the distributed setup without implementing full pairing yet
 */
public class DistributedSetupTest {

    public static void main(String[] args) {
        System.out.println("=== Testing Distributed Setup Concept ===\n");

        // We'll create a simple mock to test the MPC logic
        testSecretSharingMPC();
    }

    private static void testSecretSharingMPC() {
        System.out.println("Simulating 3-party MPC for master secret generation:\n");

        ShamirSecretSharing sss = new ShamirSecretSharing();
        java.math.BigInteger modulus = new java.math.BigInteger("340282366920938463463374607431768211297");

        int n = 3; // 3 servers
        int t = 2; // threshold 2

        // Each server generates a random contribution
        System.out.println("Phase 1: Each server generates secret contribution");
        java.math.BigInteger contrib1 = new java.math.BigInteger("111111");
        java.math.BigInteger contrib2 = new java.math.BigInteger("222222");
        java.math.BigInteger contrib3 = new java.math.BigInteger("333333");

        System.out.println("  Server 1 contributes: " + contrib1);
        System.out.println("  Server 2 contributes: " + contrib2);
        System.out.println("  Server 3 contributes: " + contrib3);

        // True master secret (unknown to any single server)
        java.math.BigInteger masterSecret = contrib1.add(contrib2).add(contrib3).mod(modulus);
        System.out.println("\nHidden master secret = " + masterSecret);

        // Each server splits their contribution
        System.out.println("Phase 2: Each server splits their contribution");
        var shares1 = sss.split(contrib1, n, t, modulus);
        var shares2 = sss.split(contrib2, n, t, modulus);
        var shares3 = sss.split(contrib3, n, t, modulus);
        System.out.println("  Server 1 creates shares of their contribution");
        System.out.println("  Server 2 creates shares of their contribution");
        System.out.println("  Server 3 creates shares of their contribution\n");

        // Each server receives one share from each other server
        System.out.println("Phase 3: Servers exchange shares");

        // Server 1 receives: share_1 from all servers
        java.math.BigInteger server1FinalShare = shares1.get(0).getValue()
                .add(shares2.get(0).getValue())
                .add(shares3.get(0).getValue())
                .mod(modulus);

        // Server 2 receives: share_2 from all servers
        java.math.BigInteger server2FinalShare = shares1.get(1).getValue()
                .add(shares2.get(1).getValue())
                .add(shares3.get(1).getValue())
                .mod(modulus);

        // Server 3 receives: share_3 from all servers
        java.math.BigInteger server3FinalShare = shares1.get(2).getValue()
                .add(shares2.get(2).getValue())
                .add(shares3.get(2).getValue())
                .mod(modulus);

        System.out.println("  Server 1 received and combined shares");
        System.out.println("  Server 2 received and combined shares");
        System.out.println("  Server 3 received and combined shares\n");

        // Test reconstruction with any 2 servers
        System.out.println("Phase 4: Test reconstruction with threshold");

        var finalShares = java.util.List.of(
                new SecretSharingScheme.Share(1, server1FinalShare),
                new SecretSharingScheme.Share(2, server2FinalShare)
        );

        java.math.BigInteger reconstructed = sss.reconstruct(finalShares, modulus);

        System.out.println("Using servers 1 and 2 to reconstruct:");
        System.out.println("  Reconstructed secret: " + reconstructed);
        System.out.println("  Original secret:      " + masterSecret);
        System.out.println("  Match: " + reconstructed.equals(masterSecret));

        var finalShares23 = java.util.List.of(
                new SecretSharingScheme.Share(1, server1FinalShare),
                new SecretSharingScheme.Share(2, server2FinalShare)
        );

        java.math.BigInteger reconstructed23 = sss.reconstruct(finalShares23, modulus);

        System.out.println("Using servers 1 and 2 to reconstruct:");
        System.out.println("  Reconstructed secret: " + reconstructed23);
        System.out.println("  Original secret:      " + masterSecret);
        System.out.println("  Match: " + reconstructed.equals(masterSecret));


    }
}