package ibe.core.interfaces;

/**
 * Interface for elliptic curve parameters.
 * Allows switching between different curve types.
 */
public interface CurveParameters {

    /**
     * Get the security level in bits
     */
    int getSecurityLevel();

    /**
     * Get curve type identifier
     */
    String getCurveType();

    /**
     * Get curve-specific parameters as string
     * Format depends on the pairing library being used
     */
    String getParametersString();

    /**
     * Get description of the curve
     */
    String getDescription();
}