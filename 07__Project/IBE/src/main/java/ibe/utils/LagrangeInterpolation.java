package ibe.utils;

import ibe.core.interfaces.SecretSharingScheme.Share;
import java.math.BigInteger;
import java.util.List;

/**
 * Utility for Lagrange interpolation in threshold cryptography
 */
public class LagrangeInterpolation {

    /**
     * Compute Lagrange coefficient for polynomial interpolation at x=0
     *
     * For reconstructing f(0) from shares, we compute:
     * λᵢ = ∏(j/(j-i)) for all j in shares where j ≠ i
     *
     * @param shares All shares being used
     * @param targetIndex The index i for which to compute coefficient
     * @param modulus The modulus for arithmetic
     * @return The Lagrange coefficient
     */
    public static BigInteger computeCoefficient(
            List<Share> shares,
            int targetIndex,
            BigInteger modulus) {

        BigInteger numerator = BigInteger.ONE;
        BigInteger denominator = BigInteger.ONE;

        for (Share share : shares) {
            int j = share.getIndex();

            if (j != targetIndex) {
                // Numerator: multiply by j (since we evaluate at x=0)
                numerator = numerator.multiply(BigInteger.valueOf(j)).mod(modulus);

                // Denominator: multiply by (j - i)
                int diff = j - targetIndex;
                denominator = denominator.multiply(BigInteger.valueOf(diff)).mod(modulus);
            }
        }

        // Return numerator / denominator mod modulus
        // Division in modular arithmetic is multiplication by modular inverse
        BigInteger denomInverse = denominator.modInverse(modulus);
        return numerator.multiply(denomInverse).mod(modulus);
    }

    /**
     * Reconstruct value at x=0 from shares
     *
     * f(0) = Σ (λᵢ * f(xᵢ)) where λᵢ is Lagrange coefficient
     *
     * @param shares The shares to use for reconstruction
     * @param modulus The modulus for arithmetic
     * @return f(0)
     */
    public static BigInteger interpolate(List<Share> shares, BigInteger modulus) {
        BigInteger result = BigInteger.ZERO;

        for (Share share : shares) {
            BigInteger coeff = computeCoefficient(shares, share.getIndex(), modulus);
            BigInteger term = coeff.multiply(share.getValue()).mod(modulus);
            result = result.add(term).mod(modulus);
        }

        return result;
    }
}