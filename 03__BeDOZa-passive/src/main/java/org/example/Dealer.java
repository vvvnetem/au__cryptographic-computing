package org.example;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Dealer {
    private Random random;
    private List<AndTriple> aliceAndTriples;
    private List<AndTriple> bobAndTriples;

    static class AndTriple {
        int u, v, w;

        AndTriple(int u, int v, int w) {
            this.u = u; this.v = v; this.w = w;
        }
    }

    public void init() {
        random = new Random();
        aliceAndTriples = new ArrayList<>();
        bobAndTriples = new ArrayList<>();

        // Generate AND triples for the circuit
        // Our formula needs 5 AND gates (3 for negations converted to AND, 2 for final ANDs)
        for (int i = 0; i < 5; i++) {
            generateAndTriple();
        }

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

        aliceAndTriples.add(new AndTriple(uA, vA, wA));
        bobAndTriples.add(new AndTriple(uB, vB, wB));
    }

    public List<AndTriple> getAliceAndTriples() {
        return aliceAndTriples;
    }

    public List<AndTriple> getBobAndTriples() {
        return bobAndTriples;
    }
}
