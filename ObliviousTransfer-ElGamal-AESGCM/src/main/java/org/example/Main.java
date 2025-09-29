
package org.example;

import java.util.Random;

public class Main {
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

    public static void main(String[] args) {
        Random random = new Random();

        int aliceBloodTypeIndex = random.nextInt(8);
        int bobBloodTypeIndex = random.nextInt(8);

        ElGamalAESGCM elGamal = new ElGamalAESGCM();
        Alice alice = new Alice(aliceBloodTypeIndex, elGamal);
        Bob bob = new Bob(bobBloodTypeIndex, elGamal);

        ElGamalAESGCM.PublicKey[] publicKeys = alice.createPublicKeys();
        ElGamalAESGCM.Ciphertext[] ciphertexts = bob.encryptBloodType(publicKeys);
        byte[] resultBytes = alice.retrieveResult(ciphertexts);

        boolean result = resultBytes.length > 0 && resultBytes[0] == 1;

        System.out.println("Alice's blood type: " + BLOOD_TYPES[aliceBloodTypeIndex]);
        System.out.println("Bob's blood type: " + BLOOD_TYPES[bobBloodTypeIndex]);
        System.out.println("Compatibility (from matrix): " +
                (COMPATIBILITY_MATRIX[aliceBloodTypeIndex][bobBloodTypeIndex] == 1 ? "Yes" : "No"));
        System.out.println("Encrypted protocol result: " + (result ? "Yes" : "No"));
    }
}
