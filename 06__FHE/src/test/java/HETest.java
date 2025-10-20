import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Exhaustive homomorphic 8×8 blood-type compatibility test using precomputed lookup table.
 * Ensures consistency between plaintext logic and encrypted (lookup-based) evaluation.
 */
public class HETest {

    private static final String[] NAMES = {"O−","O+","A−","A+","B−","B+","AB−","AB+"};

    /**
     * Plaintext ABO+Rh compatibility computation (matches Bob’s lookup table).
     */
    private static int computePlaintext(int donorIndex, int recipientIndex) {
        int d0 = (donorIndex >> 0) & 1; // Rh
        int d1 = (donorIndex >> 1) & 1; // B
        int d2 = (donorIndex >> 2) & 1; // A
        int r0 = (recipientIndex >> 0) & 1; // Rh
        int r1 = (recipientIndex >> 1) & 1; // B
        int r2 = (recipientIndex >> 2) & 1; // A

        // --- ABO Compatibility ---
        // Donor O (00): universal donor
        // Donor A (10): can donate to A or AB
        // Donor B (01): can donate to B or AB
        // Donor AB (11): can donate only to AB
        boolean abo;
        if (d1 == 0 && d2 == 0) {
            abo = true; // O → all
        } else if (d2 == 1 && d1 == 0) {
            abo = (r2 == 1); // A → A, AB
        } else if (d2 == 0 && d1 == 1) {
            abo = (r1 == 1); // B → B, AB
        } else {
            abo = (r2 == 1 && r1 == 1); // AB → AB only
        }

        // --- Rh Compatibility ---
        // Rh− → both; Rh+ → Rh+ only
        boolean rh = (d0 == 0) || (r0 == 1);

        return (abo && rh) ? 1 : 0;
    }


    @Test
    @DisplayName("Homomorphic 8×8 blood-type compatibility test (lookup table)")
    void testAllCombinations() throws Exception {
        Alice alice = new Alice(256);
        Bob bob = new Bob();

        Homomorphic.Ciphertext encZero = alice.encryptBit(0);
        Homomorphic.Ciphertext encOne  = alice.encryptBit(1);

        for (int recipient = 0; recipient < 8; recipient++) {
            for (int donor = 0; donor < 8; donor++) {
                // Encrypt donor and recipient blood types
                Homomorphic.Ciphertext[] donorC = alice.encryptBloodType(donor);
                Homomorphic.Ciphertext[] recipC = alice.encryptBloodType(recipient);

                // Evaluate homomorphic compatibility using lookup table
                Homomorphic.Ciphertext outCipher =
                        bob.evaluateCompatibility3Bit(donorC, recipC, encZero, encOne, alice.getKeyPair().getPublic(), alice);

                int secureResult = alice.decrypt(outCipher);
                int expected = computePlaintext(donor, recipient);

                // COmment here:
                String msg = String.format("[%02d] Recipient %s ← Donor %s | Expected=%d, Homomorphic output bit=%d",
                        recipient * 8 + donor + 1, NAMES[recipient], NAMES[donor], expected, secureResult);

                assertEquals(expected, secureResult, msg);
                System.out.println(" OK " + msg);
            }
        }

        System.out.println("\n✅ All homomorphic 8×8 blood-type compatibility tests passed successfully!");
    }

}
