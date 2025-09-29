import org.example.Alice;
import org.example.Bob;
import org.example.ElGamal;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class OTTest {
    public static final int[][] COMPATIBILITY_MATRIX = {
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
    void testAllBloodTypePairings() {
        System.out.println("Testing all blood type pairings:");
        int counter = 0;

        for (int recipient = 0; recipient < BLOOD_TYPES.length; recipient++) {
            for (int donor = 0; donor < BLOOD_TYPES.length; donor++) {
                ElGamal elGamal = new ElGamal();
                Alice alice = new Alice(recipient, elGamal);
                Bob bob = new Bob(donor, elGamal);

                ElGamal.PublicKey[] publicKeys = alice.createPublicKeys();
                ElGamal.Ciphertext[] ciphertexts = bob.encryptBloodType(publicKeys);

                BigInteger result = alice.retrieveResult(ciphertexts);
                BigInteger expected = BigInteger.valueOf(COMPATIBILITY_MATRIX[recipient][donor]);

                counter++;

                String errorMessage = String.format(
                        "Test %d: Compatibility mismatch for recipient %s and donor %s: Expected %s but got %s",
                        counter, BLOOD_TYPES[recipient], BLOOD_TYPES[donor], expected, result
                );

                assertEquals(expected, result, errorMessage);

                System.out.println(counter + ". Passed: " + BLOOD_TYPES[donor] + " -> " + BLOOD_TYPES[recipient]
                        + " Expected: " + expected + ", Actual: " + result);
            }
        }
    }
}
