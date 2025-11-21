package ibe.threshold;

import ibe.core.PrivateKey;
import ibe.core.SystemParameters;
import ibe.core.interfaces.HashFunction;
import ibe.core.interfaces.PairingScheme;
import ibe.core.interfaces.SecretSharingScheme;
import ibe.utils.LagrangeInterpolation;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles threshold key extraction where a user obtains their private key
 * by contacting t-out-of-n servers and combining partial keys.
 */
public class ThresholdKeyExtraction {

    /**
     * User requests their private key from multiple servers.
     *
     * Process:
     * 1. User contacts at least t servers
     * 2. Each server generates a partial key
     * 3. User verifies each partial key
     * 4. User combines partial keys using Lagrange interpolation
     *
     * @param identity The user's identity
     * @param servers List of servers to contact (must have at least t servers)
     * @param systemParameters The system parameters
     * @return The user's complete private key
     */
    public static PrivateKey extractPrivateKey(
            String identity,
            List<PKGServer> servers,
            SystemParameters systemParameters) {

        System.out.println("\n=== Threshold Key Extraction ===");
        System.out.printf("User '%s' requesting private key\n", identity);
        System.out.printf("Contacting %d servers (threshold = %d)\n\n",
                servers.size(), systemParameters.getThreshold());

        // Validate we have enough servers
        if (servers.size() < systemParameters.getThreshold()) {
            throw new IllegalArgumentException(
                    String.format("Need at least %d servers, only got %d",
                            systemParameters.getThreshold(), servers.size()));
        }

        // Step 1: Get partial keys from each server
        List<PartialPrivateKey> partialKeys = new ArrayList<>();
        for (PKGServer server : servers) {
            PartialPrivateKey partialKey = server.generatePartialKey(identity);
            partialKeys.add(partialKey);
        }
        System.out.println();

        // Step 2: Verify each partial key (simplified)
        System.out.println("--- Verifying Partial Keys ---");
        for (int i = 0; i < partialKeys.size(); i++) {
            PartialPrivateKey partialKey = partialKeys.get(i);
            PKGServer server = servers.get(i);

            boolean valid = server.verifyPartialKey(partialKey);
            if (valid) {
                System.out.printf("✓ Partial key from %s verified\n", server.getServerName());
            } else {
                throw new SecurityException(
                        String.format("✗ Partial key from %s FAILED verification!",
                                server.getServerName()));
            }
        }
        System.out.println();

        // Step 2.5: Final verification - reconstruct and check against public key
        System.out.println("--- Final Verification ---");
        verifyReconstructedKey(identity, partialKeys, systemParameters);

        // Step 3: Combine partial keys using Lagrange interpolation
        System.out.println("--- Combining Partial Keys ---");
        PrivateKey privateKey = combinePartialKeys(identity, partialKeys, systemParameters);

        System.out.println("✓ Private key reconstructed successfully\n");

        return privateKey;
    }

    /**
     * Verify that the reconstructed private key is correct.
     * Check: e(reconstructedKey, P) = e(QID, Ppub)
     */
    private static void verifyReconstructedKey(
            String identity,
            List<PartialPrivateKey> partialKeys,
            SystemParameters systemParameters) {

        PairingScheme pairing = systemParameters.getPairing();
        HashFunction hashFunc = systemParameters.getHashFunction();

        // Combine the partial keys
        PairingScheme.G1Element combinedKey = combinePartialKeysElement(partialKeys, systemParameters);

        // Get QID and Ppub
        PairingScheme.G1Element QID = hashFunc.hashToG1(identity, pairing);
        PairingScheme.G1Element P = systemParameters.getGenerator();
        PairingScheme.G1Element Ppub = systemParameters.getPublicKey();

        // Verify: e(combinedKey, P) = e(QID, Ppub)
        PairingScheme.G2Element left = pairing.pair(combinedKey, P);
        PairingScheme.G2Element right = pairing.pair(QID, Ppub);

        if (left.equals(right)) {
            System.out.println("✓ Reconstructed key verified against public parameters");
        } else {
            throw new SecurityException("✗ Reconstructed key verification FAILED!");
        }
    }

    /**
     * Helper to combine partial keys and return the G1 element
     */
    private static PairingScheme.G1Element combinePartialKeysElement(
            List<PartialPrivateKey> partialKeys,
            SystemParameters systemParameters) {

        PairingScheme pairing = systemParameters.getPairing();
        BigInteger modulus = pairing.getGroupOrder();

        // Create shares for Lagrange interpolation
        List<SecretSharingScheme.Share> shares = new ArrayList<>();
        for (PartialPrivateKey partialKey : partialKeys) {
            shares.add(new SecretSharingScheme.Share(
                    partialKey.getServerIndex(),
                    BigInteger.ZERO
            ));
        }

        // Start with identity element
        PairingScheme.G1Element combinedKey = pairing.getG1Identity();

        // Compute: finalKey = Σ (λ_i * partialKey_i)
        for (PartialPrivateKey partialKey : partialKeys) {
            BigInteger lambda = LagrangeInterpolation.computeCoefficient(
                    shares,
                    partialKey.getServerIndex(),
                    modulus
            );

            PairingScheme.G1Element weighted = partialKey.getPartialKey().multiply(lambda);
            combinedKey = combinedKey.add(weighted);
        }

        return combinedKey;
    }

    /**
     * Combine partial keys using Lagrange interpolation.
     *
     * finalKey = Σ (λ_i * partialKey_i)
     * where λ_i are Lagrange coefficients
     *
     * @param identity The user's identity
     * @param partialKeys List of partial keys from servers
     * @param systemParameters System parameters
     * @return Complete private key
     */
    private static PrivateKey combinePartialKeys(
            String identity,
            List<PartialPrivateKey> partialKeys,
            SystemParameters systemParameters) {

        PairingScheme pairing = systemParameters.getPairing();
        BigInteger modulus = pairing.getGroupOrder();

        // Create shares for Lagrange interpolation
        List<SecretSharingScheme.Share> shares = new ArrayList<>();
        for (PartialPrivateKey partialKey : partialKeys) {
            // We don't need the actual share values, just the indices
            shares.add(new SecretSharingScheme.Share(
                    partialKey.getServerIndex(),
                    BigInteger.ZERO // placeholder
            ));
        }

        // Start with identity element
        PairingScheme.G1Element combinedKey = pairing.getG1Identity();

        // Compute: finalKey = Σ (λ_i * partialKey_i)
        for (int i = 0; i < partialKeys.size(); i++) {
            PartialPrivateKey partialKey = partialKeys.get(i);

            // Compute Lagrange coefficient for this server
            BigInteger lambda = LagrangeInterpolation.computeCoefficient(
                    shares,
                    partialKey.getServerIndex(),
                    modulus
            );

            // Compute: λ_i * partialKey_i
            PairingScheme.G1Element weighted = partialKey.getPartialKey().multiply(lambda);

            // Add to combined key
            combinedKey = combinedKey.add(weighted);

            System.out.printf("Added contribution from server %d (λ=%s...)\n",
                    partialKey.getServerIndex(),
                    lambda.toString().substring(0, Math.min(10, lambda.toString().length())));
        }

        return new PrivateKey(identity, combinedKey);
    }
}