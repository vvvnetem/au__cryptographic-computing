package ibe.core.interfaces;

import java.math.BigInteger;

/**
 * Interface for pluggable hash functions.
 * Allows switching between SHA-256, SHA-3, etc.
 */
public interface HashFunction {

    /**
     * H1: Hash arbitrary string to G1 element
     * Used to convert identities to group elements
     */
    PairingScheme.G1Element hashToG1(String identity, PairingScheme pairing);

    /**
     * H2: Hash G2 element to bit string
     * Used for masking in encryption
     */
    byte[] hashToBytes(PairingScheme.G2Element element, int outputLength);

    /**
     * H3: Hash two byte arrays to Zq
     * Used to derive random value r
     */
    BigInteger hashToZq(byte[] sigma, byte[] message, BigInteger q);

    /**
     * H4: Hash byte array to bit string
     * Used for message masking
     */
    byte[] hashToBytes(byte[] input, int outputLength);

    /**
     * Get name of hash function
     */
    String getName();
}