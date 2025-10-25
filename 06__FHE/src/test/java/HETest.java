import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Exhaustive Paillier-homomorphic 8×8 blood-type compatibility test.
 * Tests that Bob’s additive homomorphic evaluation (using plaintext donor bits)
 * matches the expected plaintext compatibility logic.
 */
public class HETest {

    private static final String[] NAMES = {"O−","O+","A−","A+","B−","B+","AB−","AB+"};

    /**
     * Plaintext ABO+Rh compatibility computation.
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
        // Donor A (10): to A, AB
        // Donor B (01): to B, AB
        // Donor AB (11): to AB only
        boolean abo;
        if (d1 == 0 && d2 == 0) abo = true;
        else if (d2 == 1 && d1 == 0) abo = (r2 == 1);
        else if (d2 == 0 && d1 == 1) abo = (r1 == 1);
        else abo = (r2 == 1 && r1 == 1);

        // --- Rh Compatibility ---
        boolean rh = (d0 == 0) || (r0 == 1);

        return (abo && rh) ? 1 : 0;
    }

    @Test
    @DisplayName("Paillier-homomorphic 8×8 blood-type compatibility test")
    void testAllCombinations() throws Exception {
        // Initialize Alice (key generation) and Bob
        Alice alice = new Alice(512); // 512-bit Paillier keys for testing
        Bob bob = new Bob();

        for (int recipient = 0; recipient < 8; recipient++) {
            // Alice prepares recipient payload (encrypted masks)
            Alice.RecipientPayload payload = alice.prepareRecipientPayload(recipient);

            for (int donor = 0; donor < 8; donor++) {
                // Donor bits (plaintext)
                int donorRh = (donor >> 0) & 1;
                int donorB  = (donor >> 1) & 1;
                int donorA  = (donor >> 2) & 1;

                // Bob evaluates homomorphically
                Paillier.Ciphertext encResult = bob.evaluateCompatibility(
                        donorRh, donorB, donorA, payload, alice.getKeyPair().getPublic());

                // Alice decrypts result
                int secureResult = alice.decrypt(encResult);
                int expected = computePlaintext(donor, recipient);

                String msg = String.format("[%02d] Recipient %-3s ← Donor %-3s | Expected=%d, Homomorphic=%d",
                        recipient * 8 + donor + 1, NAMES[recipient], NAMES[donor], expected, secureResult);

                assertEquals(expected, secureResult, msg);
                System.out.println(" OK " + msg);
            }
        }

        System.out.println("\n All Paillier-homomorphic 8×8 blood-type compatibility tests passed successfully!");
    }
}
