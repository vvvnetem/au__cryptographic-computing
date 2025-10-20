
import java.util.Random;

/**
 * Demo runner: pick random Alice & Bob types and run the protocol.
 */
public class Main {
    private static final int[][] ALL_BLOOD_TYPES = {
            {0,0,0},{0,0,1},{0,1,0},{0,1,1},
            {1,0,0},{1,0,1},{1,1,0},{1,1,1}
    };
    private static final String[] NAMES = {"O-","O+","B-","B+","A-","A+","AB-","AB+"};

    public static void main(String[] args) throws Exception {
        Random rnd = new Random();

        int aliceIndex = rnd.nextInt(8);
        int bobIndex = rnd.nextInt(8);
        int[] aliceBits = ALL_BLOOD_TYPES[aliceIndex];
        int[] bobBits   = ALL_BLOOD_TYPES[bobIndex];

        System.out.println("Alice (Recipient): " + NAMES[aliceIndex]);
        System.out.println("Bob   (Donor)    : " + NAMES[bobIndex]);

        // Bob garbles circuit
        Bob bob = new Bob();
        bob.garbleCircuit();

        // Alice setup
        Alice alice = new Alice(aliceBits);

        // OT for each of Alice's 3 input wires
        for (int i = 0; i < 3; i++) {
            java.math.BigInteger C = bob.chooseC();
            // Alice creates betas
            ElGamalOT.ReceiverState rstate = alice.prepareOTReceiver(bob.ot, i, C);
            // Bob obtains s0,s1 for wire i
            byte[][] s = bob.getS0S1ForAliceIndex(i);
            // Bob responds (sender)
            ElGamalOT.SenderOutput so = bob.respondToOT(s[0], s[1], rstate.beta0, rstate.beta1, C);
            // Alice recovers
            alice.recoverFromOT(bob.ot, i, so);
        }

        // Bob encodes his input labels and sends to Alice
        alice.setBobEncodedInputs(bob.encodeBobInputs(bobBits));

        // Alice evaluates
        byte[] finalLabel = alice.evaluateGarbledCircuit(bob.garbledCircuit);

        // Bob decodes
        int result = bob.decodeOutput(finalLabel);

        System.out.println("Compatibility: " + (result == 1 ? "Bob can donate to Alice" : "Bob cannot donate to Alice"));
    }
}
