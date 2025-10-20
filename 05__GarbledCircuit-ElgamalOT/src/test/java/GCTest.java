import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exhaustive JUnit test for all 8×8 blood type compatibility combinations.
 * Each test run performs a full secure protocol execution (ElGamal OT + Garbled Circuit)
 * and compares the result to the expected logical function:
 *
 *     f(x,y) = (xA ∨ ¬yA) ∧ (xB ∨ ¬yB) ∧ (xR ∨ ¬yR)
 */
public class GCTest {

    private static final int[][] ALL_BLOOD_TYPES = {
            {0,0,0}, {0,0,1}, {0,1,0}, {0,1,1},
            {1,0,0}, {1,0,1}, {1,1,0}, {1,1,1}
    };

    private static final String[] NAMES = {
            "O-", "O+", "B-", "B+", "A-", "A+", "AB-", "AB+"
    };

    @Test
    @DisplayName("Full 8×8 blood type compatibility matrix")
    void testAllCombinations() throws Exception {
        System.out.println("🔬 Starting exhaustive 8×8 blood-type compatibility test...");

        int count = 0;
        for (int recipient = 0; recipient < 8; recipient++) {
            for (int donor = 0; donor < 8; donor++) {
                count++;

                int[] aliceBits = ALL_BLOOD_TYPES[recipient];
                int[] bobBits = ALL_BLOOD_TYPES[donor];

                // Step 1: Bob garbles the circuit
                Bob bob = new Bob();
                bob.garbleCircuit();

                // Step 2: Alice initializes with her bits
                Alice alice = new Alice(aliceBits);

                // Step 3: Run 3 rounds of OT for Alice’s input bits
                for (int i = 0; i < 3; i++) {
                    java.math.BigInteger C = bob.chooseC();
                    ElGamalOT.ReceiverState rstate = alice.prepareOTReceiver(bob.ot, i, C);
                    byte[][] s = bob.getS0S1ForAliceIndex(i);
                    ElGamalOT.SenderOutput so = bob.respondToOT(s[0], s[1], rstate.beta0, rstate.beta1, C);
                    alice.recoverFromOT(bob.ot, i, so);
                }

                // Step 4: Bob encodes his own input labels and sends them to Alice
                alice.setBobEncodedInputs(bob.encodeBobInputs(bobBits));

                // Step 5: Alice evaluates the garbled circuit
                byte[] outputLabel = alice.evaluateGarbledCircuit(bob.garbledCircuit);

                // Step 6: Bob decodes the output
                int secureResult = bob.decodeOutput(outputLabel);

                // Expected logical function result
                int expected = computePlaintext(aliceBits, bobBits) ? 1 : 0;

                String msg = String.format(
                        "[%02d] Recipient %-3s ← Donor %-3s | Expected output =%d Received output =%d",
                        count, NAMES[recipient], NAMES[donor], expected, secureResult
                );

                assertEquals(expected, secureResult, msg);
                System.out.println(" OK " + msg);
            }
        }

        System.out.println("\n All 64 compatibility tests passed successfully!");
    }

    /** Plaintext compatibility logic: (xA ∨ ¬yA) ∧ (xB ∨ ¬yB) ∧ (xR ∨ ¬yR) */
    private static boolean computePlaintext(int[] x, int[] y) {
        boolean termA = (x[0] == 1) || (y[0] == 0);
        boolean termB = (x[1] == 1) || (y[1] == 0);
        boolean termR = (x[2] == 1) || (y[2] == 0);
        return termA && termB && termR;
    }
}
