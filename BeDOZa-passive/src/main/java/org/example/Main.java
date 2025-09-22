package org.example;

import java.util.Arrays;
import java.util.Map;
import java.util.Random;

public class Main {

    private static final int[] O_NEGATIVE = new int[]{0, 0, 0};
    private static final int[] O_POSITIVE = new int[]{0, 0, 1};
    private static final int[] B_NEGATIVE = new int[]{0, 1, 0};
    private static final int[] B_POSITIVE = new int[]{0, 1, 1};
    private static final int[] A_NEGATIVE = new int[]{1, 0, 0};
    private static final int[] A_POSITIVE = new int[]{1, 0, 1};
    private static final int[] AB_NEGATIVE = new int[]{1, 1, 0};
    private static final int[] AB_POSITIVE = new int[]{1, 1, 1};

    // Array of all blood types for iteration
    private static final int[][] ALL_BLOOD_TYPES = {
            O_NEGATIVE, O_POSITIVE, B_NEGATIVE, B_POSITIVE,
            A_NEGATIVE, A_POSITIVE, AB_NEGATIVE, AB_POSITIVE
    };

    private static final String[] BLOOD_TYPE_NAMES = {
            "O-", "O+", "B-", "B+", "A-", "A+", "AB-", "AB+"
    };

    public static void main(String[] args) {

        Random random = new Random();
        Dealer dealer = new Dealer();
        Alice alice = new Alice();
        Bob bob = new Bob();

        //genrate random blood types for Alice and Bob
        int aliceTypeIndex = random.nextInt(8);
        int bobTypeIndex = random.nextInt(8);
        int[] aliceBloodType = ALL_BLOOD_TYPES[aliceTypeIndex];
        int[] bobBloodType = ALL_BLOOD_TYPES[bobTypeIndex];


        dealer.init();
        alice.init(aliceBloodType, dealer.getAliceAndTriples());
        bob.init(bobBloodType, dealer.getBobAndTriples());

        bob.receiveShares(alice.sendBShares());
        alice.receiveShares(bob.sendAShares());

        alice.computeNegationsAndXor();
        bob.computeNegationsAndXor();

        int[] aliceMasks = alice.createMasksForFirstLevelAnds();
        int[] bobMasks = bob.computeFirstLevelAnds(aliceMasks);
        alice.computeFirstLevelAnds(bobMasks);

        alice.computeLastXors();
        bob.computeLastXors();

        int[] aliceMasksForSecondLevelAnd = alice.createMasksForSecondLevelAnd();
        int[] bobMasksForSecondLevelAnd = bob.computeSecondLevelAnd(aliceMasksForSecondLevelAnd);
        alice.computeSecondLevelAnd(bobMasksForSecondLevelAnd);

        int[] aliceMasksForThirdLevelAnd = alice.createMasksForThirdLevelAnd();
        int[] bobMasksForThirdLevelAnd = bob.computeThirdLevelAnd(aliceMasksForThirdLevelAnd);
        alice.computeThirdLevelAnd(bobMasksForThirdLevelAnd);

        // Final output phase - Bob sends his share to Alice
        int bobFinalShare = bob.sendFinalShare();
        int finalResult = alice.computeFinalResult(bobFinalShare);

        System.out.println("Alice blood type: " + BLOOD_TYPE_NAMES[aliceTypeIndex]);
        System.out.println("Bob blood type: " + BLOOD_TYPE_NAMES[bobTypeIndex]);
        String resultMessage = finalResult == 1 ? "Bob can donate blood to Alice." : "Bob cannot be a donor for Alice.";
        System.out.println("Alice learns the result: " + resultMessage );

    }
}