package ibe.core.interfaces;

import java.math.BigInteger;

/**
 * Interface for pluggable pairing implementations.
 * Allows switching between Weil, Tate, or other pairings.
 */
public interface PairingScheme {

    /**
     * Represents an element in group G1 (additive group)
     */
    interface G1Element {
        G1Element add(G1Element other);
        G1Element multiply(BigInteger scalar);
        G1Element duplicate();
        boolean equals(Object other);
        boolean isIdentity();
        byte[] toBytes();
        int getByteLength();
    }

    /**
     * Represents an element in group G2/GT (multiplicative group)
     */
    interface G2Element {
        G2Element multiply(G2Element other);
        G2Element pow(BigInteger exponent);
        G2Element duplicate();
        boolean equals(Object other);
        boolean isIdentity();
        byte[] toBytes();
        int getByteLength();
    }

    /**
     * Get the order of the groups
     */
    BigInteger getGroupOrder();

    /**
     * Get a random generator of G1
     */
    G1Element getG1Generator();

    /**
     * Get a random element from G1
     */
    G1Element getRandomG1Element();

    /**
     * Get identity element of G1
     */
    G1Element getG1Identity();

    /**
     * Get identity element of G2
     */
    G2Element getG2Identity();

    /**
     * Compute the pairing e(P, Q)
     * @param p Element from G1
     * @param q Element from G1
     * @return Element in G2
     */
    G2Element pair(G1Element p, G1Element q);

    /**
     * Parse G1 element from bytes
     */
    G1Element g1FromBytes(byte[] bytes);

    /**
     * Parse G2 element from bytes
     */
    G2Element g2FromBytes(byte[] bytes);

    /**
     * Get name/description of this pairing scheme
     */
    String getName();
}