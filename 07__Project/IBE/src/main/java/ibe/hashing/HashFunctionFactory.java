package ibe.hashing;

import ibe.core.interfaces.HashFunction;

/**
 * Factory for creating hash function implementations.
 * Allows easy switching between different hash algorithms.
 */
public class HashFunctionFactory {

    /**
     * Create default hash function (SHA-256)
     */
    public static HashFunction createDefault() {
        return new SHA256HashFunction();
    }

    /**
     * Create SHA-256 based hash function
     */
    public static HashFunction createSHA256() {
        return new SHA256HashFunction();
    }

    // Future: Could add other hash functions
    // public static HashFunction createSHA3() { ... }
    // public static HashFunction createBlake2() { ... }
}