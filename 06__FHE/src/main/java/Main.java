import java.util.Random;

public class Main {
    private static final String[] NAMES = {"O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"};

    public static void main(String[] args) throws Exception {
        Random rnd = new Random();
        int recipientIndex = rnd.nextInt(8);
        int donorIndex = rnd.nextInt(8);

        System.out.println("Recipient: " + NAMES[recipientIndex]);
        System.out.println("Donor    : " + NAMES[donorIndex]);

        Alice alice = new Alice(256);
        Bob bob = new Bob();

        // Encrypt bits 0 and 1
        Homomorphic.Ciphertext encZero = alice.encryptBit(0);
        Homomorphic.Ciphertext encOne  = alice.encryptBit(1);

        // Encrypt donor and recipient blood types
        Homomorphic.Ciphertext[] donorEnc = alice.encryptBloodType(donorIndex);
        Homomorphic.Ciphertext[] recipEnc = alice.encryptBloodType(recipientIndex);

        // Evaluate compatibility using lookup table (multiplicative depth = 0)
        Homomorphic.Ciphertext encryptedResult =
                bob.evaluateCompatibility3Bit(donorEnc, recipEnc, encZero, encOne, alice.getKeyPair().getPublic(), alice);

        // Decrypt the result
        int result = alice.decrypt(encryptedResult);

        System.out.println("Compatible? " + (result == 1 ? "YES" : "❌ NO"));
    }
}
