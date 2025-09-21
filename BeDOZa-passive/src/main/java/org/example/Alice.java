package org.example;

import java.util.Random;

public class Alice {
    private final Random random = new Random();
    int x1a;
    int x2a;
    int x3a;

    int x1b;
    int x2b;
    int x3b;

    int y1a;
    int y2a;
    int y3a;

    int notY1a;
    int notY2a;
    int notY3a;

    int x1aXorNotY1a;
    int x2aXorNotY2a;
    int x3aXorNotY3a;

    int x1aAndNotY1a;
    int x2aAndNotY2a;
    int x3aAndNotY3a;

    int lastXor1a;
    int lastXor2a;
    int lastXor3a;

    int secondLevelAnda;
    int thirdLevelAnda;

    private Dealer dealer;

    public void setDealer(Dealer dealer) {
        this.dealer = dealer;
    }

    public void init(int[] input) {
        int x1 = input[0];
        x1b = random.nextInt(2);
        x1a = x1 ^ x1b;

        int x2 = input[1];
        x2b = random.nextInt(2);
        x2a = x2 ^ x2b;

        int x3 = input[2];
        x3b = random.nextInt(2);
        x3a = x3 ^ x3b;
    }

    public int[] sendBShares() {
        return new int[]{x1b, x2b, x3b};
    }

    public void receiveShares(int[] shares) {
        y1a = shares[0];
        y2a = shares[1];
        y3a = shares[2];

        notY1a = y1a ^ 1;
        notY2a = y2a ^ 1;
        notY3a = y3a ^ 1;
    }

    public void computeNegationsAndXor() {
        //Compute XOR parts
        x1aXorNotY1a = x1a ^ notY1a;
        x2aXorNotY2a = x2a ^ notY2a;
        x3aXorNotY3a = x3a ^ notY3a;

    }

    public int[] createMasksForFirstLevelAnds() {

        // For the AND parts, we need to compute: x1∧¬y1, x2∧¬y2, x3∧¬y3
        // We'll store the da, ea values to use later
        int[] masks = new int[6]; // Store da, ea for each of the 3 AND gates

        // Prepare masks for all three AND gates
        //Dealer.AndTriple triple1 = dealer.getTriple(0);
        Dealer.AndTriple triple1 = dealer.getTriple(0);
        masks[0] = x1a ^ triple1.uA; // da for first AND
        masks[1] = notY1a ^ triple1.vA; // ea for first AND

        Dealer.AndTriple triple2 = dealer.getTriple(1);
        masks[2] = x2a ^ triple2.uA; // da for second AND
        masks[3] = notY2a ^ triple2.vA; // ea for second AND

        Dealer.AndTriple triple3 = dealer.getTriple(2);
        masks[4] = x3a ^ triple3.uA; // da for third AND
        masks[5] = notY3a ^ triple3.vA; // ea for third AND

        return masks; // Send these to Bob
    }

    public int[] processAndGate(int[] bobMessage, int tripleIndex, int xa, int ya) {
        // Get Bob's masks
        int db = bobMessage[0];
        int eb = bobMessage[1];

        // Get multiplication triple from dealer
        Dealer.AndTriple triple = dealer.getTriple(tripleIndex);

        // Compute ALice's masks
        int da = xa ^ triple.uA;
        int ea = ya ^ triple.vA;

        // Reconstruct the opened values (same as Alice does)
        int d = db ^ da;
        int e = eb ^ ea;

        // Compute Bob's share of the result
        int za = triple.wA ^ (e & xa) ^ (d & ya) ^ (e & d);

        // Send Bob's masks back to Alice
        return new int[]{da, ea, za}; // Include result share
    }

    public int[] computeFirstLevelAnds(int[] bobMasks) {

        // Process all three AND gates
        int[] aliceMasks = new int[6]; // we already have this, but for symmetry

        // Process first AND: x1 ∧ ¬y1
        int[] msg1 = new int[]{bobMasks[0], bobMasks[1]};
        int[] resp1 = processAndGate(msg1, 0, x1a, notY1a);
        aliceMasks[0] = resp1[0]; // da for first AND
        aliceMasks[1] = resp1[1]; // ea for first AND
        x1aAndNotY1a = resp1[2]; // za for first AND

        // Process second AND: x2 ∧ ¬y2
        int[] msg2 = new int[]{bobMasks[2], bobMasks[3]};
        int[] resp2 = processAndGate(msg2, 1, x2a, notY2a);
        aliceMasks[2] = resp2[0]; // da for second AND
        aliceMasks[3] = resp2[1]; // ea for second AND
        x2aAndNotY2a = resp2[2]; // za for second AND

        // Process third AND: x3 ∧ ¬y3
        int[] msg3 = new int[]{bobMasks[4], bobMasks[5]};
        int[] resp3 = processAndGate(msg3, 2, x3a, notY3a);
        aliceMasks[4] = resp3[0]; // da for third AND
        aliceMasks[5] = resp3[1]; // ea for third AND
        x3aAndNotY3a = resp3[2]; // za for third AND

        return aliceMasks;
    }

    public void computeLastXors() {
        lastXor1a = x1aXorNotY1a ^ x1aAndNotY1a;
        lastXor2a = x2aXorNotY2a ^ x2aAndNotY2a;
        lastXor3a = x3aXorNotY3a ^ x3aAndNotY3a;
    }

    public int[] createMasksForSecondLevelAnd() {
        int[] aliceMask = new int[2]; // Store da, ea

        // Prepare mask
        Dealer.AndTriple triple = dealer.getTriple(3);
        aliceMask[0] = lastXor1a ^ triple.uA; // da for first AND
        aliceMask[1] = lastXor2a ^ triple.vA;

        return aliceMask; // Send these to Bob
    }

    public int[] computeSecondLevelAnd(int[] bobMasksForSecondLevelAnd) {
        int[] aliceMask = new int[2]; //we already have this, but for symmetry

        int[] resp1 = processAndGate(bobMasksForSecondLevelAnd, 3, lastXor1a, lastXor2a);
        aliceMask[0] = resp1[0]; // da
        aliceMask[1] = resp1[1]; // ea
        secondLevelAnda = resp1[2]; // za

        return aliceMask;
    }

    public int[] createMasksForThirdLevelAnd() {
        int[] aliceMask = new int[2]; // Store da, ea

        // Prepare mask
        Dealer.AndTriple triple = dealer.getTriple(4);
        aliceMask[0] = secondLevelAnda ^ triple.uA; // da for first AND
        aliceMask[1] = lastXor3a ^ triple.vA;

        return aliceMask; // Send these to Bob
    }

    public int[] computeThirdLevelAnd(int[] bobMasksForThirdLevelAnd) {
        int[] aliceMask = new int[2]; //we already have this, but for symmetry

        int[] resp1 = processAndGate(bobMasksForThirdLevelAnd, 4, secondLevelAnda, lastXor3a);
        aliceMask[0] = resp1[0]; // da
        aliceMask[1] = resp1[1]; // ea
        thirdLevelAnda = resp1[2]; // za

        return aliceMask;
    }

    public int computeFinalResult(int bobFinalShare) {
        return thirdLevelAnda ^ bobFinalShare;
    }


    public int[] createMask(int x, int y) {
        int[] mask = new int[2];
        Dealer.AndTriple triple1 = dealer.getTriple(0);
        mask[0] = x ^ triple1.uA; // da for first AND
        mask[1] = y ^ triple1.vA; // ea for first AND

        return mask;
    }

    public int compute(int[] bobMasks, int x, int y) {
        Dealer.AndTriple triple = dealer.getTriple(0);
        int da = x ^ triple.uA;
        int ea = y ^ triple.vA;

        // Reconstruct the opened values (same as Alice does)
        int d = bobMasks[0] ^ da;
        int e = bobMasks[1] ^ ea;

        return triple.wA ^ (e & x) ^ (d & y) ^ (e & d);
    }
}
