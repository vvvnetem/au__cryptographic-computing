import java.util.Random;

public class Main {
    private static final String[] NAMES = {"O-","O+","A-","A+","B-","B+","AB-","AB+"};

    public static void main(String[] args) throws Exception {
        // Key size: 1024-bit modulus (for demo). For production use 2048+ bits.
        Alice alice = new Alice(1024);
        Paillier.KeyPair kp = alice.getKeyPair();
        Paillier.PublicKey pub = kp.getPublic(); // use getter from Paillier

        Bob bob = new Bob();
        Random rnd = new Random();

        int recipient = rnd.nextInt(8);
        int donor = rnd.nextInt(8);

        System.out.println("Recipient: " + NAMES[recipient]);
        System.out.println("Donor    : " + NAMES[donor]);

        // Alice prepares encrypted payload for recipient and sends to Bob
        Alice.RecipientPayload payload = alice.prepareRecipientPayload(recipient);

        // Bob computes final compatibility using his plaintext donor bits
        int donorRh = (donor >> 0) & 1;
        int donorB  = (donor >> 1) & 1;
        int donorA  = (donor >> 2) & 1;

        Paillier.Ciphertext out = bob.evaluateCompatibility(donorRh, donorB, donorA, payload, pub);

        // Alice decrypts result
        int result = alice.decrypt(out);
        System.out.println("Compatible? " + (result == 1 ? "YES" : "NO"));
    }
}
