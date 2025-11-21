package ibe.core.interfaces;

import java.math.BigInteger;
import java.util.List;

/**
 * Interface for threshold secret sharing schemes.
 * Allows switching between Shamir, Feldman, or other schemes.
 */
public interface SecretSharingScheme {

    /**
     * Represents a share of a secret
     */
    class Share {
        private final int index;        // x-coordinate (1, 2, 3, ...)
        private final BigInteger value; // y-coordinate (the share)

        public Share(int index, BigInteger value) {
            this.index = index;
            this.value = value;
        }

        public int getIndex() { return index; }
        public BigInteger getValue() { return value; }
    }

    /**
     * Split a secret into n shares, requiring t to reconstruct
     * @param secret The secret to split
     * @param n Total number of shares
     * @param t Threshold (minimum shares needed)
     * @param modulus The modulus for arithmetic
     * @return List of n shares
     */
    List<Share> split(BigInteger secret, int n, int t, BigInteger modulus);

    /**
     * Reconstruct secret from at least t shares
     * @param shares List of at least t shares
     * @param modulus The modulus for arithmetic
     * @return The reconstructed secret
     */
    BigInteger reconstruct(List<Share> shares, BigInteger modulus);

    /**
     * Compute Lagrange coefficient for given shares at x=0
     * @param shares The shares being used for reconstruction
     * @param targetIndex The index for which to compute coefficient
     * @param modulus The modulus for arithmetic
     * @return Lagrange coefficient
     */
    BigInteger computeLagrangeCoefficient(List<Share> shares, int targetIndex, BigInteger modulus);

    /**
     * Get name of the scheme
     */
    String getName();
}