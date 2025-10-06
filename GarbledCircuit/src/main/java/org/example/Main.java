package org.example;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) throws Exception {
        // Alice's input (recipient): xA, xB, xR (e.g., A+ = 1,0,1)
        int[] aliceInput = {0, 0, 0}; // A+

        // Bob's input (donor): yA, yB, yR (e.g., O+ = 0,0,1)
        int[] bobInput = {1, 0, 0}; // O+

        System.out.println("Blood Compatibility Check using Garbled Circuits");
        System.out.println("================================================");
        System.out.println("Alice (Recipient): " + bloodTypeString(aliceInput));
        System.out.println("Bob (Donor): " + bloodTypeString(bobInput));
        System.out.println();

        // Step 1: Bob garbles the circuit
        Bob bob = new Bob();
        bob.garbleCircuit();

        // Step 2: Bob sends garbled circuit to Alice
        GarbledGate[] garbledCircuit = bob.getGarbledCircuit();

        // Step 3: Bob encodes his own input
        WireLabel[] bobInputLabels = bob.encodeBobInput(bobInput);

        // Step 4: Oblivious Transfer for Alice's input
        // Bob provides both labels for each of Alice's input wires
        WireLabel[][] aliceInputLabelChoices = bob.getAliceInputLabels();
        // Alice receives only the labels corresponding to her input
        WireLabel[] aliceInputLabels = SimulatedOT.simulateOT(aliceInputLabelChoices, aliceInput);

        // Step 5: Bob sends output decoding information
        WireLabel[] outputDecoding = bob.getOutputDecoding();

        // Step 6: Alice evaluates the garbled circuit
        Alice alice = new Alice();
        boolean compatible = alice.evaluateCircuit(
                garbledCircuit,
                aliceInputLabels,
                bobInputLabels,
                outputDecoding
        );

        System.out.println("Result: " + (compatible ? "COMPATIBLE" : "NOT COMPATIBLE"));
        System.out.println();

        // Verify with plaintext computation
        boolean expected = computePlaintext(aliceInput, bobInput);
        System.out.println("Verification (plaintext): " + (expected ? "COMPATIBLE" : "NOT COMPATIBLE"));
        System.out.println("Match: " + (compatible == expected ? "YES" : "NO"));
    }

    private static boolean computePlaintext(int[] x, int[] y) {
        // f(x, y) = (xA ∨ ¬yA) ∧ (xB ∨ ¬yB) ∧ (xR ∨ ¬yR)
        boolean termA = (x[0] == 1) || (y[0] == 0);
        boolean termB = (x[1] == 1) || (y[1] == 0);
        boolean termR = (x[2] == 1) || (y[2] == 0);
        return termA && termB && termR;
    }

    private static String bloodTypeString(int[] input) {
        String type = "";
        if (input[0] == 1 && input[1] == 1) type = "AB";
        else if (input[0] == 1) type = "A";
        else if (input[1] == 1) type = "B";
        else type = "O";
        type += (input[2] == 1) ? "+" : "-";
        return type;
    }
}
