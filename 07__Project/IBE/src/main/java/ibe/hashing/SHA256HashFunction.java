package ibe.hashing;

import ibe.core.interfaces.HashFunction;
import ibe.core.interfaces.PairingScheme;
import ibe.pairing.JPBCPairingScheme;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The hash function implementation is tightly coupled to JPBC,
 * which is fine since we're using JPBC as our pairing library.
 * If we later want to support other pairing libraries,
 * we'd need to make the hash function more generic
 * or have different implementations for each library.
 */

/**
 * Implementation of hash functions H1, H2, H3, H4 using SHA-256.
 *
 * H1: Identity → G1 (hash identity strings to group elements)
 * H2: G2 → {0,1}^n (hash group elements to bit strings)
 * H3: {0,1}^n × {0,1}^n → Zq (hash two byte arrays to integers mod q)
 * H4: {0,1}^n → {0,1}^n (hash byte array to bit string)
 */
public class SHA256HashFunction implements HashFunction {

    private static final String HASH_ALGORITHM = "SHA-256";

    /**
     * Get a SHA-256 message digest instance
     */
    private MessageDigest getDigest() {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * H1: Hash identity string to G1 element
     *
     * Process:
     * 1. Hash the identity string using SHA-256
     * 2. Use the hash output to deterministically generate a G1 element
     * 3. Uses setFromHash() which is designed for this purpose in JPBC
     *
     * @param identity The identity string (e.g., "bob@company.com")
     * @param pairing The pairing scheme
     * @return A deterministic G1 element derived from the identity
     */
    @Override
    public PairingScheme.G1Element hashToG1(String identity, PairingScheme pairing) {
        // We need to access the JPBC pairing - cast to our implementation
        if (!(pairing instanceof JPBCPairingScheme)) {
            throw new IllegalArgumentException("Pairing must be JPBCPairingScheme");
        }

        JPBCPairingScheme jpbcPairing = (JPBCPairingScheme) pairing;
        Pairing actualPairing = jpbcPairing.getJPBCPairing();

        // Convert identity to bytes
        byte[] identityBytes = identity.getBytes(StandardCharsets.UTF_8);

        // Hash the identity
        MessageDigest digest = getDigest();
        byte[] hash = digest.digest(identityBytes);

        // Create G1 element from hash
        // JPBC's setFromHash creates a deterministic element from bytes
        Element element = actualPairing.getG1().newElement();

        // setFromHash takes bytes and deterministically maps to group element
        element.setFromHash(hash, 0, hash.length);
        element = element.getImmutable();

        // Wrap in our interface
        return new JPBCPairingScheme.JPBCGroup1Element(element, actualPairing);
    }

    /**
     * H2: Hash G2 element to byte string of specified length
     *
     * Process:
     * 1. Convert G2 element to bytes
     * 2. Hash using SHA-256
     * 3. Expand to desired length using KDF (Key Derivation Function)
     *
     * @param element The G2 element to hash
     * @param outputLength Desired output length in bytes
     * @return Byte array of specified length
     */
    @Override
    public byte[] hashToBytes(PairingScheme.G2Element element, int outputLength) {
        // Get bytes from G2 element
        byte[] elementBytes = element.toBytes();

        // Use KDF to expand to desired length
        return kdf(elementBytes, outputLength);
    }

    /**
     * H3: Hash two byte arrays to Zq (integer modulo q)
     *
     * Process:
     * 1. Concatenate sigma and message
     * 2. Hash using SHA-256
     * 3. Convert to BigInteger and reduce modulo q
     *
     * @param sigma Random value (byte array)
     * @param message The message (byte array)
     * @param q The modulus (group order)
     * @return BigInteger in range [0, q-1]
     */
    @Override
    public BigInteger hashToZq(byte[] sigma, byte[] message, BigInteger q) {
        // Concatenate inputs
        byte[] combined = new byte[sigma.length + message.length];
        System.arraycopy(sigma, 0, combined, 0, sigma.length);
        System.arraycopy(message, 0, combined, sigma.length, message.length);

        // Hash
        MessageDigest digest = getDigest();
        byte[] hash = digest.digest(combined);

        // Convert to BigInteger (always positive)
        BigInteger result = new BigInteger(1, hash);

        // Reduce modulo q
        result = result.mod(q);

        // Ensure non-zero (map 0 to 1)
        if (result.equals(BigInteger.ZERO)) {
            result = BigInteger.ONE;
        }

        return result;
    }

    /**
     * H4: Hash byte array to byte string of specified length
     *
     * Process:
     * 1. Hash input using SHA-256
     * 2. Expand to desired length using KDF
     *
     * @param input The input byte array
     * @param outputLength Desired output length in bytes
     * @return Byte array of specified length
     */
    @Override
    public byte[] hashToBytes(byte[] input, int outputLength) {
        return kdf(input, outputLength);
    }

    /**
     * Key Derivation Function (KDF) based on SHA-256
     *
     * Expands input to arbitrary length using counter mode:
     * Output = Hash(input || 0) || Hash(input || 1) || Hash(input || 2) || ...
     *
     * This is similar to the KDF used in standards like NIST SP 800-56C
     *
     * @param input The input bytes
     * @param outputLength Desired output length in bytes
     * @return Expanded byte array
     */
    private byte[] kdf(byte[] input, int outputLength) {
        MessageDigest digest = getDigest();
        int hashLength = digest.getDigestLength(); // SHA-256 = 32 bytes

        // Calculate how many hash iterations we need
        int iterations = (outputLength + hashLength - 1) / hashLength;

        byte[] result = new byte[outputLength];
        int offset = 0;

        // Generate enough hash output
        for (int i = 0; i < iterations; i++) {
            // Hash(input || counter)
            digest.reset();
            digest.update(input);
            digest.update((byte) (i >> 24));
            digest.update((byte) (i >> 16));
            digest.update((byte) (i >> 8));
            digest.update((byte) i);

            byte[] hash = digest.digest();

            // Copy to result (may be partial on last iteration)
            int copyLength = Math.min(hash.length, outputLength - offset);
            System.arraycopy(hash, 0, result, offset, copyLength);
            offset += copyLength;
        }

        return result;
    }

    @Override
    public String getName() {
        return "SHA-256 Hash Functions";
    }
}