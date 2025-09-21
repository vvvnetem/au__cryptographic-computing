package org.example;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Dealer {
    private Random random;
    private List<AndTriple> andTriples;

    static class AndTriple {
        // For Alice
        int uA, vA, wA;
        // For Bob
        int uB, vB, wB;

        AndTriple(int uA, int vA, int wA, int uB, int vB, int wB) {
            this.uA = uA; this.vA = vA; this.wA = wA;
            this.uB = uB; this.vB = vB; this.wB = wB;
        }
    }

    public void init() {
        random = new Random();
        andTriples = new ArrayList<>();

        // Generate AND triples for the circuit
        // Our formula needs 5 AND gates (3 for negations converted to AND, 2 for final ANDs)
        for (int i = 0; i < 5; i++) {
            generateAndTriple();
        }

        //andTriples.add(new AndTriple(1, 1, 0, 0, 1, 0));
    }

    private void generateAndTriple() {
        // Generate random u, v
        int u = random.nextInt(2);
        int v = random.nextInt(2);
        int w = u * v;

        // Generate random shares
        int uA = random.nextInt(2);
        int uB = u ^ uA;

        int vA = random.nextInt(2);
        int vB = v ^ vA;

        int wA = random.nextInt(2);
        int wB = w ^ wA;

        andTriples.add(new AndTriple(uA, vA, wA, uB, vB, wB));
    }

    public AndTriple getTriple(int index) {
        if (index < andTriples.size()) {
            return andTriples.get(index);
        }
        return null;
    }

}
