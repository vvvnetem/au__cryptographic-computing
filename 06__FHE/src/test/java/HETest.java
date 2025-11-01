import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Exhaustive 8x8 test for blood compatibility using the d-HE scheme.
 */
public class HETest {

    private static final String[] NAMES = {"O-","O+","A-","A+","B-","B+","AB-","AB+"};

    /**
     * Plaintext compatibility check for validation.
     * donor and recipient are encoded as 3-bit integers: bit0=Rh, bit1=B, bit2=A
     */
    private int plaintextCompatibility(int donor, int recipient) {
        int d0 = (donor >> 0) & 1;
        int d1 = (donor >> 1) & 1;
        int d2 = (donor >> 2) & 1;
        int r0 = (recipient >> 0) & 1;
        int r1 = (recipient >> 1) & 1;
        int r2 = (recipient >> 2) & 1;

        boolean abo;
        if (d1 == 0 && d2 == 0) abo = true;               // O donor
        else if (d2 == 1 && d1 == 0) abo = (r2 == 1);     // A donor
        else if (d2 == 0 && d1 == 1) abo = (r1 == 1);     // B donor
        else abo = (r2 == 1 && r1 == 1);                  // AB donor

        boolean rh = (d0 == 0) || (r0 == 1);
        return (abo && rh) ? 1 : 0;
    }

    @Test
    public void testAllPairs() throws Exception {
        Alice alice = new Alice();
        Bob bob = new Bob();

        for (int recipient = 0; recipient < 8; recipient++) {
            // Encrypt recipient blood type bits
            Alice.RecipientPayload payload = alice.prepareRecipientPayload(recipient);

            for (int donor = 0; donor < 8; donor++) {
                int donorRh = (donor >> 0) & 1;
                int donorB  = (donor >> 1) & 1;
                int donorA  = (donor >> 2) & 1;

                // Bob evaluates encrypted compatibility
                DHE.Ciphertext out = bob.evaluateCompatibility(
                        donorRh, donorB, donorA,
                        payload,
                        alice.getKeyPair().getPublic(),
                        alice.getKeyPair().getPrivate()
                );

                // Alice decrypts
                int hom = alice.decrypt(out);
                int plain = plaintextCompatibility(donor, recipient);

                // Assert correctness
                assertEquals(plain, hom,
                        String.format("Recipient %s <- Donor %s: expected=%d got=%d",
                                NAMES[recipient], NAMES[donor], plain, hom));

                System.out.println(String.format("OK: Recipient %s <- Donor %s: %d",
                        NAMES[recipient], NAMES[donor], hom));
            }
        }
        System.out.println(" ============================ ");
        System.out.println("All tests passed.");
    }
}
