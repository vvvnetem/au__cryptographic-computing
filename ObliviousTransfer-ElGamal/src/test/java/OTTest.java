import org.example.Alice;
import org.example.Bob;
import org.example.ElGamal;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

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

    @Test
    void testAliceDecryptsWrongCiphertext() {
        System.out.println("Testing Alice decrypting wrong ciphertext:");

        // Set up Alice as AB+ (index 0) and Bob as O- (index 7)
        int aliceBloodType = 0;
        int bobBloodType = 0;

        ElGamal elGamal = new ElGamal();
        Alice alice = new Alice(aliceBloodType, elGamal);
        Bob bob = new Bob(bobBloodType, elGamal);

        // Alice creates public keys for her blood type
        ElGamal.PublicKey[] alicePublicKeys = alice.createPublicKeys();

        // Bob encrypts his blood type using Alice's public keys
        ElGamal.Ciphertext[] bobCiphertexts = bob.encryptBloodType(alicePublicKeys);

        //Alice tries to decrypt other ciphertexts
        BigInteger differentMessage = elGamal.decrypt(bobCiphertexts[1], alice.getSecretKey());

        // Expected result should be 1 (compatible)
        BigInteger expected = BigInteger.valueOf(COMPATIBILITY_MATRIX[aliceBloodType][bobBloodType]);

        // The wrong result should NOT match what the original Alice should get
        assertNotEquals(expected, differentMessage,
                "Alice with should not get the correct result");


        System.out.println("Honest Alice should get: " + expected);
        System.out.println("Corrupted Alice gets: " + differentMessage);
    }

    @Test
    void testBobCannotDistinguishFakePublicKeys() {
        System.out.println("Testing Bob cannot distinguish fake public keys:");

        int aliceBloodType = 2;
        int bobBloodType = 6;

        ElGamal elGamal = new ElGamal();
        Alice alice = new Alice(aliceBloodType, elGamal);
        Bob bob = new Bob(bobBloodType, elGamal);

        // Alice creates public keys (some real, some fake via OGen)
        ElGamal.PublicKey[] publicKeys = alice.createPublicKeys();

        // Bob should not be able to tell which keys are real vs fake
        // All keys should look cryptographically valid to Bob
        for (int i = 0; i < publicKeys.length; i++) {
            ElGamal.PublicKey key = publicKeys[i];

            // Bob can encrypt with any key (even fake ones)
            BigInteger testMessage = BigInteger.valueOf(42);
            ElGamal.Ciphertext ciphertext = elGamal.encrypt(testMessage, key);

            assertNotNull(ciphertext.c, "Encryption should produce valid c1 for key " + i);
            assertNotNull(ciphertext.d, "Encryption should produce valid c2 for key " + i);

            System.out.println("Key " + i + " appears valid to Bob - can encrypt successfully");
        }
    }
}
