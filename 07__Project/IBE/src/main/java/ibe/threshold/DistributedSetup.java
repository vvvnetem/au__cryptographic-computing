package ibe.threshold;

import ibe.core.SystemParameters;
import ibe.core.MasterKeyShare;
import ibe.core.interfaces.PairingScheme;
import ibe.core.interfaces.HashFunction;
import ibe.core.interfaces.SecretSharingScheme;
import ibe.core.interfaces.SecretSharingScheme.Share;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Distributed setup for IBE system using MPC.
 *
 * Three servers work together to create:
 * 1. A shared master secret (split among them)
 * 2. System public parameters
 *
 * No single server learns the complete master secret.
 */
public class DistributedSetup {

    /**
     * Represents a server participating in the distributed setup
     */
    public static class Server {
        private final int index;
        private final String name;
        private final SecureRandom random;

        // Each server's contribution to the master secret
        private BigInteger secretContribution;

        // Each server's share after distribution
        private MasterKeyShare finalShare;

        public Server(int index, String name) {
            this.index = index;
            this.name = name;
            this.random = new SecureRandom();
        }

        public int getIndex() { return index; }
        public String getName() { return name; }
        public MasterKeyShare getFinalShare() { return finalShare; }

        /**
         * Phase 1: Each server generates their random contribution
         */
        public BigInteger generateContribution(BigInteger modulus) {
            this.secretContribution = new BigInteger(modulus.bitLength(), random).mod(modulus);
            if (this.secretContribution.equals(BigInteger.ZERO)) {
                this.secretContribution = BigInteger.ONE;
            }
            System.out.printf("%s generated secret contribution (kept private)\n", name);
            return this.secretContribution;
        }

        /**
         * Phase 2: Each server computes their public commitment
         */
        public PairingScheme.G1Element computePublicCommitment(
                BigInteger contribution,
                PairingScheme.G1Element generator) {

            PairingScheme.G1Element commitment = generator.multiply(contribution);
            System.out.printf("%s computed public commitment\n", name);
            return commitment;
        }

        /**
         * Phase 3: Server splits their contribution and distributes shares
         */
        public List<Share> distributeShares(
                BigInteger contribution,
                int totalServers,
                int threshold,
                BigInteger modulus,
                SecretSharingScheme sharingScheme) {

            List<Share> shares = sharingScheme.split(contribution, totalServers, threshold, modulus);
            System.out.printf("%s created shares of their contribution\n", name);
            return shares;
        }

        /**
         * Phase 4: Server receives shares from all servers and combines them
         */
        public void receiveAndCombineShares(
                List<List<Share>> allShares,
                BigInteger modulus) {

            // Each server receives one share from every server (including themselves)
            // Server i receives share_i from each server

            BigInteger combinedShare = BigInteger.ZERO;

            for (int serverIdx = 0; serverIdx < allShares.size(); serverIdx++) {
                List<Share> sharesFromServer = allShares.get(serverIdx);
                // Find the share meant for this server
                Share shareForMe = sharesFromServer.get(this.index - 1);

                // Add to combined share
                combinedShare = combinedShare.add(shareForMe.getValue()).mod(modulus);
            }

            // Create the final master key share
            this.finalShare = new MasterKeyShare(this.index, new Share(this.index, combinedShare));
            System.out.printf("%s combined received shares into final share\n", name);
        }
    }

    /**
     * Result of distributed setup
     */
    public static class DistributedSetupResult {
        private final SystemParameters systemParameters;
        private final List<MasterKeyShare> serverShares;

        public DistributedSetupResult(SystemParameters systemParameters, List<MasterKeyShare> serverShares) {
            this.systemParameters = systemParameters;
            this.serverShares = serverShares;
        }

        public SystemParameters getSystemParameters() { return systemParameters; }
        public List<MasterKeyShare> getServerShares() { return serverShares; }
        public MasterKeyShare getServerShare(int serverIndex) {
            return serverShares.get(serverIndex - 1);
        }
    }

    /**
     * Run the distributed setup protocol with 3 servers.
     *
     * Protocol steps:
     * 1. Each server generates random secret contribution
     * 2. Each server computes public commitment
     * 3. Each server splits their contribution using Shamir
     * 4. Servers exchange shares (in practice, this would be encrypted)
     * 5. Each server combines received shares
     * 6. Compute final public key from commitments
     *
     * @param pairing The pairing scheme to use
     * @param hashFunction The hash function to use
     * @param messageLengthBits Message length in bits
     * @param totalServers Total number of servers (3)
     * @param threshold Threshold for reconstruction (2)
     * @return Setup result with public parameters and server shares
     */
    public static DistributedSetupResult setup(
            PairingScheme pairing,
            HashFunction hashFunction,
            int messageLengthBits,
            int totalServers,
            int threshold) {

        System.out.println("\n=== Starting Distributed IBE Setup (MPC) ===\n");
        System.out.printf("Configuration: %d servers, threshold = %d\n\n", totalServers, threshold);

        BigInteger modulus = pairing.getGroupOrder();
        SecretSharingScheme sharingScheme = new ShamirSecretSharing();

        // Create servers
        List<Server> servers = new ArrayList<>();
        servers.add(new Server(1, "Server-1"));
        servers.add(new Server(2, "Server-2"));
        servers.add(new Server(3, "Server-3"));

        // Choose generator
        PairingScheme.G1Element generator = pairing.getG1Generator();
        System.out.println("Selected generator P for group G1\n");

        // PHASE 1: Each server generates their secret contribution
        System.out.println("--- Phase 1: Secret Generation ---");
        List<BigInteger> contributions = new ArrayList<>();
        for (Server server : servers) {
            BigInteger contribution = server.generateContribution(modulus);
            contributions.add(contribution);
        }
        System.out.println();

        // PHASE 2: Each server computes their public commitment
        System.out.println("--- Phase 2: Public Commitments ---");
        List<PairingScheme.G1Element> publicCommitments = new ArrayList<>();
        for (int i = 0; i < servers.size(); i++) {
            PairingScheme.G1Element commitment =
                    servers.get(i).computePublicCommitment(contributions.get(i), generator);
            publicCommitments.add(commitment);
        }
        System.out.println();

        // PHASE 3: Each server creates shares of their contribution
        System.out.println("--- Phase 3: Share Distribution ---");
        List<List<Share>> allShares = new ArrayList<>();
        for (int i = 0; i < servers.size(); i++) {
            List<Share> shares = servers.get(i).distributeShares(
                    contributions.get(i),
                    totalServers,
                    threshold,
                    modulus,
                    sharingScheme
            );
            allShares.add(shares);
        }
        System.out.println();

        // PHASE 4: Each server receives shares and combines them
        System.out.println("--- Phase 4: Share Combination ---");
        for (Server server : servers) {
            server.receiveAndCombineShares(allShares, modulus);
        }
        System.out.println();

        // PHASE 5: Compute the public key (sum of all commitments)
        System.out.println("--- Phase 5: Public Key Generation ---");
        PairingScheme.G1Element publicKey = pairing.getG1Identity();
        for (PairingScheme.G1Element commitment : publicCommitments) {
            publicKey = publicKey.add(commitment);
        }
        System.out.println("Combined public commitments into Ppub\n");

        // Create system parameters
        PairingScheme.G1Element[] commitmentArray =
                publicCommitments.toArray(new PairingScheme.G1Element[0]);

        SystemParameters systemParameters = new SystemParameters(
                pairing,
                hashFunction,
                generator,
                publicKey,
                messageLengthBits,
                commitmentArray,
                threshold,
                totalServers
        );

        // Collect server shares
        List<MasterKeyShare> serverShares = new ArrayList<>();
        for (Server server : servers) {
            serverShares.add(server.getFinalShare());
        }

        System.out.println("=== Distributed Setup Complete ===");
        System.out.println("✓ Master secret split among " + totalServers + " servers");
        System.out.println("✓ Any " + threshold + " servers can help users");
        System.out.println("✓ No single server knows the master secret\n");

        return new DistributedSetupResult(systemParameters, serverShares);
    }
}