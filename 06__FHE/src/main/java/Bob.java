import java.security.SecureRandom;

/**
 * Bob evaluates ABO+Rh blood-type compatibility homomorphically using a lookup table.
 * Multiplicative depth = 0, values always 0/1.
 */
public class Bob {
    private final SecureRandom rnd = new SecureRandom();

    // Correct ABO+Rh compatibility table (donor × recipient)
    // Index: 3-bit blood type [Rh, B, A]
    private static final int[][] COMPAT_TABLE = {
            // O−, O+, A−, A+, B−, B+, AB−, AB+
            {1, 1, 1, 1, 1, 1, 1, 1}, // O−
            {0, 1, 0, 1, 0, 1, 0, 1}, // O+
            {0, 0, 1, 1, 0, 0, 1, 1}, // A−
            {0, 0, 0, 1, 0, 0, 0, 1}, // A+
            {0, 0, 0, 0, 1, 1, 1, 1}, // B−
            {0, 0, 0, 0, 0, 1, 0, 1}, // B+
            {0, 0, 0, 0, 0, 0, 1, 1}, // AB−
            {0, 0, 0, 0, 0, 0, 0, 1}, // AB+
    };

    /**
     * Convert 3-bit blood type ciphertexts into index 0..7
     * d0 = Rh, d1 = B, d2 = A
     */
    private int decodeBits(Homomorphic.Ciphertext[] bits, Alice alice) {
        int value = 0;
        value |= alice.decrypt(bits[2]) << 2; // A (MSB)
        value |= alice.decrypt(bits[1]) << 1; // B
        value |= alice.decrypt(bits[0]);      // Rh (LSB)
        return value;
    }
    /**
     * Evaluate 3-bit blood compatibility using precomputed table
     * Multiplicative depth = 0
     */
    public Homomorphic.Ciphertext evaluateCompatibility3Bit(
            Homomorphic.Ciphertext[] donorBits,
            Homomorphic.Ciphertext[] recipBits,
            Homomorphic.Ciphertext encZero,
            Homomorphic.Ciphertext encOne,
            Homomorphic.PublicKey pk,
            Alice alice) {

        int donorIndex = decodeBits(donorBits, alice);
        int recipIndex = decodeBits(recipBits, alice);

        int compatible = COMPAT_TABLE[donorIndex][recipIndex];

        System.out.printf("Donor index=%d, Recipient index=%d, Compatible=%d%n",
                donorIndex, recipIndex, compatible);

        // Encrypt the result (0/1)
        return alice.encryptBit(compatible);
    }
}
