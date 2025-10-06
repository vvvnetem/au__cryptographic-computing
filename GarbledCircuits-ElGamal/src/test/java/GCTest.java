import org.example.Alice;
import org.example.Bob;
import org.example.ElGamal;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class GCTest {

    private static final int[][] COMPATIBILITY_MATRIX = {
            {1, 1, 1, 1, 1, 1, 1, 1},
            {1, 0, 1, 0, 1, 0, 1, 0},
            {1, 1, 0, 0, 1, 1, 0, 0},
            {1, 0, 0, 0, 1, 0, 0, 0},
            {1, 1, 1, 1, 0, 0, 0, 0},
            {1, 0, 1, 0, 0, 0, 0, 0},
            {1, 1, 0, 0, 0, 0, 0, 0},
            {1, 0, 0, 0, 0, 0, 0, 0}
    };

    private static final String[] BLOOD_TYPES = {
            "AB+", "AB-", "A+", "A-", "B+", "B-", "O+", "O-"
    };

    @Test
    void testAllBloodTypePairings() throws Exception {
        System.out.println("🔍 Testing all blood type compatibility pairs:");
        int counter = 0;

        for (int recipient = 0; recipient < BLOOD_TYPES.length; recipient++) {
            for (int donor = 0; donor < BLOOD_TYPES.length; donor++) {
                // Initialize ElGamal with fresh parameters
                ElGamal elGamal = new ElGamal();

                // Set up Alice and Bob with their blood types
                Alice alice = new Alice(recipient, elGamal);
                Bob bob = new Bob(donor, elGamal);

                // Alice creates  public keys for OT
                ElGamal.PublicKey[] otPublicKeys = alice.createPublicKeys();

                // Bob encrypts bits of his compatibility row using Alice's public keys
                ElGamal.Ciphertext[] encryptedBits = bob.encryptBloodType(otPublicKeys);

                // Alice retrieves her output bit via OT
                BigInteger result = alice.retrieveResult(encryptedBits);
                BigInteger expected = BigInteger.valueOf(COMPATIBILITY_MATRIX[recipient][donor]);

                counter++;
                String errorMessage = String.format(
                        "Blood Test %d failed: %s <- %s | Expected: %s, Got: %s",
                        counter, BLOOD_TYPES[recipient], BLOOD_TYPES[donor], expected, result
                );

                assertEquals(expected, result, errorMessage);

                System.out.printf(" Blood Test %2d. Passed: %-3s ← %-3s | Result: %s\n",
                        counter, BLOOD_TYPES[recipient], BLOOD_TYPES[donor], result);
            }
        }

        System.out.println("\n Blood type compatibility tests passed.");
    }
}
