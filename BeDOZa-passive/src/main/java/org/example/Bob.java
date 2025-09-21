package org.example;

import java.util.Random;

public class Bob {

    private final Random random = new Random();

    int y1b;
    int y2b;
    int y3b;

    int notY1b;
    int notY2b;
    int notY3b;

    int y1a;
    int y2a;
    int y3a;

    int x1b;
    int x2b;
    int x3b;

    int x1bXorNotY1b;
    int x2bXorNotY2b;
    int x3bXorNotY3b;

    int x1bAndNotY1b;
    int x2bAndNotY2b;
    int x3bAndNotY3b;

    int lastXor1b;
    int lastXor2b;
    int lastXor3b;

    int secondLevelAndb;
    int thirdLevelAndb;

    private Dealer dealer;

    public void setDealer(Dealer dealer) {
        this.dealer = dealer;
    }

    public void init(int[] input) {

        int y1 = input[0];
        y1a = random.nextInt(2);
        y1b = y1 ^ y1a;
        notY1b = y1b; // Bob's share doesn't change for XOR with constant

        int y2 = input[1];
        y2a = random.nextInt(2);
        y2b = y2 ^ y2a;
        notY2b = y2b; // Bob's share doesn't change for XOR with constant

        int y3 = input[2];
        y3a = random.nextInt(2);
        y3b = y3 ^ y3a;
        notY3b = y3b; // Bob's share doesn't change for XOR with constant
    }

    public int[] sendAShares() {
        return new int[]{y1a, y2a, y3a};
    }

    public void receiveShares(int[] shares) {
        x1b = shares[0];
        x2b = shares[1];
        x3b = shares[2];
    }

    public void computeNegationsAndXor() {
        // Compute XOR parts
        x1bXorNotY1b = x1b ^ notY1b;
        x2bXorNotY2b = x2b ^ notY2b;
        x3bXorNotY3b = x3b ^ notY3b;
    }

    public int[] processAndGate(int[] aliceMessage, int tripleIndex, int xb, int yb) {
        // Get Alice's masks
        int da = aliceMessage[0];
        int ea = aliceMessage[1];

        // Get multiplication triple from dealer
        Dealer.AndTriple triple = dealer.getTriple(tripleIndex);

        // Compute Bob's masks
        int db = xb ^ triple.uB;
        int eb = yb ^ triple.vB;

        // Reconstruct the opened values (same as Alice does)
        int d = da ^ db;
        int e = ea ^ eb;

        // Compute Bob's share of the result
        int zb = triple.wB ^ (e & xb) ^ (d & yb) /*^ (e & d)*/;

        // Send Bob's masks back to Alice
        return new int[]{db, eb, zb}; // Include result share
    }

    public int[] computeFirstLevelAnds(int[] aliceMasks) {
        // Process all three AND gates
        int[] bobMasks = new int[6];

        // Process first AND: x1 ∧ ¬y1
        int[] msg1 = new int[]{aliceMasks[0], aliceMasks[1]};
        int[] resp1 = processAndGate(msg1, 0, x1b, notY1b);
        bobMasks[0] = resp1[0]; // db for first AND
        bobMasks[1] = resp1[1]; // eb for first AND
        x1bAndNotY1b = resp1[2]; // zb for first AND

        // Process second AND: x2 ∧ ¬y2
        int[] msg2 = new int[]{aliceMasks[2], aliceMasks[3]};
        int[] resp2 = processAndGate(msg2, 1, x2b, notY2b);
        bobMasks[2] = resp2[0]; // db for second AND
        bobMasks[3] = resp2[1]; // eb for second AND
        x2bAndNotY2b = resp2[2]; // zb for second AND

        // Process third AND: x3 ∧ ¬y3
        int[] msg3 = new int[]{aliceMasks[4], aliceMasks[5]};
        int[] resp3 = processAndGate(msg3, 2, x3b, notY3b);
        bobMasks[4] = resp3[0]; // db for third AND
        bobMasks[5] = resp3[1]; // eb for third AND
        x3bAndNotY3b = resp3[2]; // zb for third AND

        return bobMasks;
    }

    public void computeLastXors() {
        lastXor1b = x1bXorNotY1b ^ x1bAndNotY1b;
        lastXor2b = x2bXorNotY2b ^ x2bAndNotY2b;
        lastXor3b = x3bXorNotY3b ^ x3bAndNotY3b;
    }

    public int[] computeSecondLevelAnd(int[] aliceMask) {
        int[] bobMask = new int[2];

        int[] resp1 = processAndGate(aliceMask, 3, lastXor1b, lastXor2b);
        bobMask[0] = resp1[0]; // db
        bobMask[1] = resp1[1]; // eb
        secondLevelAndb = resp1[2]; // zb

        return bobMask;
    }

    public int[] computeThirdLevelAnd(int[] aliceMask) {
        int[] bobMask = new int[2];

        int[] resp1 = processAndGate(aliceMask, 4, secondLevelAndb, lastXor3b);
        bobMask[0] = resp1[0]; // db
        bobMask[1] = resp1[1]; // eb
        thirdLevelAndb = resp1[2]; // zb

        return bobMask;
    }

    public int sendFinalShare() {
        return thirdLevelAndb;
    }

    public int[] createMask(int x, int y) {
        int[] mask = new int[2];
        Dealer.AndTriple triple1 = dealer.getTriple(0);
        mask[0] = x ^ triple1.uB; // db for first AND
        mask[1] = y ^ triple1.vB; // eb for first AND

        return mask;
    }

    public int compute(int[] aliceMask, int x, int y) {
        Dealer.AndTriple triple = dealer.getTriple(0);
        int db = x ^ triple.uB;
        int eb = y ^ triple.vB;

        // Reconstruct the opened values (same as Alice does)
        int d = aliceMask[0] ^ db;
        int e = aliceMask[1] ^ eb;

        return triple.wB ^ (e & x) ^ (d & y) /*^ (e & d)*/;
    }
}
