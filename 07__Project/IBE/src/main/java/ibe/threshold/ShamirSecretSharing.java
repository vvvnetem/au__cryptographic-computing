package ibe.threshold;

import ibe.core.interfaces.SecretSharingScheme;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of Shamir's Secret Sharing Scheme.
 *
 * This scheme allows splitting a secret into n shares such that:
 * - Any t shares can reconstruct the secret
 * - Any t-1 shares reveal nothing about the secret
 *
 * The scheme works by:
 * 1. Creating a random polynomial f(x) of degree t-1 where f(0) = secret
 * 2. Evaluating f(1), f(2), ..., f(n) to get the shares
 * 3. Using Lagrange interpolation to reconstruct f(0) from any t shares
 */
public class ShamirSecretSharing implements SecretSharingScheme {

    private final SecureRandom random;

    public ShamirSecretSharing() {
        this.random = new SecureRandom();
    }

    /**
     * Split a secret into n shares with threshold t.
     *
     * Creates a polynomial: f(x) = secret + a₁x + a₂x² + ... + a_{t-1}x^{t-1}
     * where a₁, a₂, ..., a_{t-1} are random coefficients.
     *
     * @param secret The secret to split (f(0))
     * @param n Total number of shares to create
     * @param t Threshold - minimum shares needed to reconstruct
     * @param modulus The prime modulus for arithmetic
     * @return List of n shares
     */
    @Override
    public List<Share> split(BigInteger secret, int n, int t, BigInteger modulus) {
        // Validate parameters
        if (t > n) {
            throw new IllegalArgumentException("Threshold t cannot be greater than n");
        }
        if (t < 1) {
            throw new IllegalArgumentException("Threshold must be at least 1");
        }
        if (n < 1) {
            throw new IllegalArgumentException("Must create at least 1 share");
        }
        if (!modulus.isProbablePrime(100)) {
            throw new IllegalArgumentException("Modulus must be prime");
        }

        // Ensure secret is in valid range
        secret = secret.mod(modulus);

        // Create polynomial coefficients: [secret, a₁, a₂, ..., a_{t-1}]
        BigInteger[] coefficients = new BigInteger[t];
        coefficients[0] = secret; // f(0) = secret

        // Generate random coefficients a₁, a₂, ..., a_{t-1}
        for (int i = 1; i < t; i++) {
            coefficients[i] = new BigInteger(modulus.bitLength(), random).mod(modulus);
        }

        // Evaluate polynomial at x = 1, 2, 3, ..., n to create shares
        List<Share> shares = new ArrayList<>();
        for (int x = 1; x <= n; x++) {
            BigInteger y = evaluatePolynomial(coefficients, BigInteger.valueOf(x), modulus);
            shares.add(new Share(x, y));
        }

        return shares;
    }

    /**
     * Evaluate polynomial at point x.
     *
     * f(x) = c₀ + c₁x + c₂x² + ... + c_{t-1}x^{t-1}
     *
     * Uses Horner's method for efficient evaluation:
     * f(x) = c₀ + x(c₁ + x(c₂ + x(...)))
     */
    private BigInteger evaluatePolynomial(BigInteger[] coefficients, BigInteger x, BigInteger modulus) {
        BigInteger result = BigInteger.ZERO;

        // Horner's method: start from highest degree
        for (int i = coefficients.length - 1; i >= 0; i--) {
            result = result.multiply(x).add(coefficients[i]).mod(modulus);
        }

        return result;
    }

    /**
     * Reconstruct the secret from at least t shares.
     *
     * Uses Lagrange interpolation to find f(0) from the shares.
     *
     * f(0) = Σᵢ yᵢ * Lᵢ(0)
     * where Lᵢ(0) = ∏ⱼ≠ᵢ (xⱼ/(xⱼ-xᵢ))
     *
     * @param shares List of at least t shares
     * @param modulus The prime modulus for arithmetic
     * @return The reconstructed secret
     */
    @Override
    public BigInteger reconstruct(List<Share> shares, BigInteger modulus) {
        if (shares == null || shares.isEmpty()) {
            throw new IllegalArgumentException("Need at least one share");
        }

        BigInteger secret = BigInteger.ZERO;

        // For each share, compute its contribution using Lagrange basis polynomial
        for (Share share : shares) {
            BigInteger lagrangeCoeff = computeLagrangeCoefficient(shares, share.getIndex(), modulus);
            BigInteger term = share.getValue().multiply(lagrangeCoeff).mod(modulus);
            secret = secret.add(term).mod(modulus);
        }

        return secret;
    }

    /**
     * Compute Lagrange coefficient for share i when evaluating at x=0.
     *
     * Lᵢ(0) = ∏ⱼ≠ᵢ (xⱼ/(xⱼ-xᵢ))
     *
     * Since we evaluate at x=0:
     * Lᵢ(0) = ∏ⱼ≠ᵢ (xⱼ/(xⱼ-xᵢ))
     *
     * In modular arithmetic, division is multiplication by modular inverse.
     */
    @Override
    public BigInteger computeLagrangeCoefficient(List<Share> shares, int targetIndex, BigInteger modulus) {
        BigInteger numerator = BigInteger.ONE;
        BigInteger denominator = BigInteger.ONE;

        for (Share share : shares) {
            int xj = share.getIndex();

            if (xj != targetIndex) {
                // Numerator: multiply by xⱼ (since we evaluate at x=0)
                numerator = numerator.multiply(BigInteger.valueOf(xj)).mod(modulus);

                // Denominator: multiply by (xⱼ - xᵢ)
                int diff = xj - targetIndex;
                denominator = denominator.multiply(BigInteger.valueOf(diff)).mod(modulus);
            }
        }

        // Ensure denominator is positive
        if (denominator.signum() < 0) {
            denominator = denominator.add(modulus);
        }

        // Compute denominator⁻¹ mod modulus
        BigInteger denomInverse = denominator.modInverse(modulus);

        // Return numerator * denominator⁻¹ mod modulus
        return numerator.multiply(denomInverse).mod(modulus);
    }

    @Override
    public String getName() {
        return "Shamir Secret Sharing";
    }
}