package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Main {
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
    public static void main(String[] args) {
        Random random = new Random();
        ElGamal elGamal = new ElGamal();
        Alice alice = new Alice(random.nextInt(8), elGamal);
        Bob bob = new Bob(random.nextInt(8), elGamal);


        ElGamal.PublicKey[] publicKeys = alice.createPublicKeys();
        ElGamal.Ciphertext[] ciphertexts = bob.encryptBloodType(publicKeys);

        BigInteger result = alice.retrieveResult(ciphertexts);
        System.out.println("result: " + result);

        System.out.println("Alice's blood type: " + BLOOD_TYPES[alice.bloodType]);
        System.out.println("Bob's blood type: " + BLOOD_TYPES[7 - bob.bloodType]);
        System.out.println("Can Alice receive from Bob? " + (result.equals(BigInteger.ONE) ? "Yes" : "No"));

    }
}