package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

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

    public static void main(String[] args) throws Exception {
        SecureRandom random = new SecureRandom();

        // Initialize ElGamal (shared parameters)
        ElGamal elGamal = new ElGamal();

        // Randomly select Alice's and Bob's blood types
        int aliceType = random.nextInt(8);
        int bobType = random.nextInt(8);

        // Instantiate parties
        Alice alice = new Alice(aliceType, elGamal);
        Bob bob = new Bob(bobType, elGamal);

        // Alice: generate public keys for OT (one per input bit)
        ElGamal.PublicKey[] otPublicKeys = alice.createPublicKeys();

        // Bob: encrypt labels using OT based on his truth table row (donor)
        ElGamal.Ciphertext[] encryptedBits = bob.encryptBloodType(otPublicKeys);

        // Alice: retrieve the result bit (0 or 1) from OT
        BigInteger resultBit = alice.retrieveResult(encryptedBits);

        // Print results
        System.out.println("Alice's blood type: " + BLOOD_TYPES[aliceType]);
        System.out.println("Bob's blood type: " + BLOOD_TYPES[bobType]);
        System.out.println("Can Alice receive blood from Bob? " + (resultBit.equals(BigInteger.ONE) ? "✅ Yes" : "❌ No"));
    }
}
