package org.example;

public class Main {
    public static void main(String[] args) {
        Dealer dealer = new Dealer();
        Alice alice = new Alice();
        Bob bob = new Bob();

        int[] aliceBloodType = new int[]{0, 0, 0};
        int[] bobBloodType = new int[]{0, 0, 1};


        dealer.init();
        alice.init(aliceBloodType);
        bob.init(bobBloodType);

        alice.setDealer(dealer);
        bob.setDealer(dealer);

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

        System.out.println("Alice learns the result: " + finalResult);


    }
}