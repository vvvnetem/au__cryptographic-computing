import org.example.Alice;
import org.example.Bob;
import org.example.Dealer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestBeDOZa {
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

    // Blood type names for better error messages
    private static final String[] BLOOD_TYPE_NAMES = {
            "O-", "O+", "B-", "B+", "A-", "A+", "AB-", "AB+"
    };

    public int runProtocol(int[] donor, int[] recipient) {
        Dealer dealer = new Dealer();
        Alice alice = new Alice();
        Bob bob = new Bob();

        int[] aliceBloodType = recipient;
        int[] bobBloodType = donor;


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
        return alice.computeFinalResult(bobFinalShare);
    }

    /**
     * Expected compatibility using boolean formula f(x, y) = (xA ∨ ¬yA) ∧ (xB ∨ ¬yB) ∧ (xR ∨ ¬yR)
     * where x = recipient, y = donor
     */
    private int getExpectedResult(int[] donor, int[] recipient) {
        // Extract components: [A, B, Rh]
        int xA = recipient[0];  // recipient A antigen
        int xB = recipient[1];  // recipient B antigen
        int xR = recipient[2];  // recipient Rh factor

        int yA = donor[0];      // donor A antigen
        int yB = donor[1];      // donor B antigen
        int yR = donor[2];      // donor Rh factor

        // Apply boolean formula: f(x, y) = (xA ∨ ¬yA) ∧ (xB ∨ ¬yB) ∧ (xR ∨ ¬yR)
        boolean termA = (xA == 1) || (yA == 0);  // recipient has A OR donor lacks A
        boolean termB = (xB == 1) || (yB == 0);  // recipient has B OR donor lacks B
        boolean termR = (xR == 1) || (yR == 0);  // recipient has Rh+ OR donor lacks Rh+

        return (termA && termB && termR) ? 1 : 0;
    }


    @Test
    public void testAllBloodTypeCompatibilities() {
        int counter = 0;
        // Test all 64 possible combinations (8 donors × 8 recipients)
        for (int donorIndex = 0; donorIndex < ALL_BLOOD_TYPES.length; donorIndex++) {
            for (int recipientIndex = 0; recipientIndex < ALL_BLOOD_TYPES.length; recipientIndex++) {
                int[] donor = ALL_BLOOD_TYPES[donorIndex];
                int[] recipient = ALL_BLOOD_TYPES[recipientIndex];

                int expected = getExpectedResult(donor, recipient);
                int actual = runProtocol(donor, recipient);
                counter++;

                String errorMessage = String.format(
                        "Compatibility test failed for donor %s %s to recipient %s %s. Expected: %d, Actual: %d",
                        BLOOD_TYPE_NAMES[donorIndex],
                        java.util.Arrays.toString(donor),
                        BLOOD_TYPE_NAMES[recipientIndex],
                        java.util.Arrays.toString(recipient),
                        expected,
                        actual
                );

                assertEquals(expected, actual, errorMessage);
                System.out.println(counter + ". Passed: " + BLOOD_TYPE_NAMES[donorIndex] + " -> " + BLOOD_TYPE_NAMES[recipientIndex] + " Expected: " + expected + ", Actual: " + actual);
            }
        }
    }
}
