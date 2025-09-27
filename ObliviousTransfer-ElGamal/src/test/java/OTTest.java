import org.example.Alice;
import org.example.Bob;
import org.example.ElGamal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class OTTest {
    public static final int[][] COMPATIBILITY_MATRIX = {
            {1,1,1,1,1,1,1,1},
            {1,0,1,0,1,0,1,0},
            {1,1,0,0,1,1,0,0},
            {1,0,0,0,1,0,0,0},
            {1,1,1,1,0,0,0,0},
            {1,0,1,0,0,0,0,0},
            {1,1,0,0,0,0,0,0},
            {1,0,0,0,0,0,0,0}
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

                // Check compatibility based on matrix
                BigInteger expected = BigInteger.valueOf(COMPATIBILITY_MATRIX[recipient][donor]);

                counter++;
                assertEquals(expected, result,
                        String.format("Compatibility check failed for %s (recipient) and %s (donor)",
                                BLOOD_TYPES[recipient], BLOOD_TYPES[donor]));

                System.out.println(counter + ". Passed: " + BLOOD_TYPES[7-donor] + " -> " + BLOOD_TYPES[recipient] + " Expected: " + expected + ", Actual: " + result);
            }
        }
    }



    private boolean checkCompatibility(int recipient, int donor) {
        return COMPATIBILITY_MATRIX[recipient][donor] == 1;
    }
}
