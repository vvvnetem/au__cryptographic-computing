import java.util.Random;

/**
 * Demo run: random recipient (Alice) and donor (Bob) using DHE scheme.
 */
public class Main {
    private static final String[] NAMES = {"O-","O+","A-","A+","B-","B+","AB-","AB+"};

    public static void main(String[] args) throws Exception {
        Alice alice = new Alice();
        Bob bob = new Bob();

        // pick random donor & recipient
        Random rnd = new Random();
        int recipient = rnd.nextInt(8);
        int donor = rnd.nextInt(8);

        System.out.println("Recipient: " + NAMES[recipient]);
        System.out.println("Donor    : " + NAMES[donor]);

        // Alice prepares payload and sends to Bob
        Alice.RecipientPayload payload = alice.prepareRecipientPayload(recipient);

        // Bob computes
        int donorRh = (donor >> 0) & 1;
        int donorB  = (donor >> 1) & 1;
        int donorA  = (donor >> 2) & 1;

        DHE.Ciphertext result = bob.evaluateCompatibility(donorRh, donorB, donorA,
                payload, alice.getKeyPair().getPublic(), alice.getKeyPair().getPrivate());

        // Alice decrypts
        int dec = alice.decrypt(result);
        System.out.println("Compatible? " + (dec == 1 ? "YES" : "NO"));
    }
}
