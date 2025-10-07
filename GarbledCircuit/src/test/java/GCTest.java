package org.example;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

public class GCTest {

    @Test
    @DisplayName("Test all blood type compatibility combinations")
    public void testAllBloodTypeCompatibility() throws Exception {
        // Define all 8 blood types
        int[][] bloodTypes = {
            {0, 0, 0}, // O-
            {0, 0, 1}, // O+
            {1, 0, 0}, // A-
            {1, 0, 1}, // A+
            {0, 1, 0}, // B-
            {0, 1, 1}, // B+
            {1, 1, 0}, // AB-
            {1, 1, 1}  // AB+
        };

        String[] bloodTypeNames = {"O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"};

        System.out.println("\n=== Blood Type Compatibility Test Results ===\n");
        System.out.println("Testing all 64 combinations (8 recipients x 8 donors)");
        System.out.println("Format: Recipient ← Donor | Expected | Actual | Status");
        System.out.println("--------------------------------------------------------");

        int passedTests = 0;
        int failedTests = 0;

        // Test all 64 combinations (8 recipients x 8 donors)
        for (int recipientIdx = 0; recipientIdx < 8; recipientIdx++) {
            for (int donorIdx = 0; donorIdx < 8; donorIdx++) {
                int[] recipientInput = bloodTypes[recipientIdx];
                int[] donorInput = bloodTypes[donorIdx];

                // Calculate expected result using plaintext computation
                boolean expected = computePlaintext(recipientInput, donorInput);

                // Run the garbled circuit protocol
                Bob bob = new Bob();
                bob.garbleCircuit();

                GarbledGate[] garbledCircuit = bob.getGarbledCircuit();
                WireLabel[] bobInputLabels = bob.encodeBobInput(donorInput);
                WireLabel[][] aliceInputLabelChoices = bob.getAliceInputLabels();
                WireLabel[] aliceInputLabels = SimulatedOT.simulateOT(aliceInputLabelChoices, recipientInput);
                WireLabel[] outputDecoding = bob.getOutputDecoding();

                Alice alice = new Alice();
                boolean actual = alice.evaluateCircuit(
                    garbledCircuit,
                    aliceInputLabels,
                    bobInputLabels,
                    outputDecoding
                );

                String status = (actual == expected) ? "✓ PASS" : "✗ FAIL";

                if (actual == expected) {
                    passedTests++;
                } else {
                    failedTests++;
                }

                // Print result for each combination
                System.out.printf("%-4s ← %-4s | %-13s | %-13s | %s\n",
                    bloodTypeNames[recipientIdx],
                    bloodTypeNames[donorIdx],
                    expected ? "COMPATIBLE" : "NOT COMPATIBLE",
                    actual ? "COMPATIBLE" : "NOT COMPATIBLE",
                    status);

                // Assert that the result matches expected
                assertEquals(expected, actual,
                    String.format("Compatibility check failed: Recipient %s ← Donor %s",
                        bloodTypeNames[recipientIdx],
                        bloodTypeNames[donorIdx]));
            }
        }

        System.out.println("--------------------------------------------------------");
        System.out.printf("Total: 64 | Passed: %d | Failed: %d\n", passedTests, failedTests);
        System.out.println("==========================================================\n");
    }

    private static boolean computePlaintext(int[] x, int[] y) {
        // f(x, y) = (xA ∨ ¬yA) ∧ (xB ∨ ¬yB) ∧ (xR ∨ ¬yR)
        boolean termA = (x[0] == 1) || (y[0] == 0);
        boolean termB = (x[1] == 1) || (y[1] == 0);
        boolean termR = (x[2] == 1) || (y[2] == 0);
        return termA && termB && termR;
    }
}
