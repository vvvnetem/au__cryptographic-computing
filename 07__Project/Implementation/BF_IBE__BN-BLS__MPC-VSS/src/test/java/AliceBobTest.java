// Import Part Members
import Client.Alice;
import Client.Bob;

// Import classes for IBE, ECC, MPC
import crypto.BF_IBE;
import crypto.DPK;
import crypto.ThresholdCryptography;

// Import classes for ECC (Pairing) specific computation
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class AliceBobTest {

    static Pairing pairing;
    static BigInteger prime, masterSeed;
    static BF_IBE ibe;
    static DPK dpk;
    static Alice alice;
    static Bob bob;

    @BeforeAll
    static void setup() {

        // Load BN254 Type F pairing parameters
        pairing = PairingFactory.getPairing("bn254.properties");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);

        prime = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        masterSeed = new BigInteger(256, new Random());

        // Convert BigInteger → byte[] for HKDF
        byte[] seedBytes = masterSeed.toByteArray();
        BigInteger msk = ThresholdCryptography.hkdf(seedBytes, "IBE-BN", prime);

        // Initialize BF_IBE with BN254
        ibe = new BF_IBE(msk, "bn254");

        dpk = new DPK(4, 3, prime, masterSeed);

        alice = new Alice("alice@home", ibe);
        bob = new Bob("bob@home", dpk, ibe);
    }

    @Test
    void testAliceBobEncryptionDecryption() {
        String messageStr = "Hello Bob, this is Alice!";
        byte[] msgBytes = messageStr.getBytes();

        // Hash message into Zr, then map to G1
        BigInteger h = new BigInteger(1, msgBytes).mod(pairing.getZr().getOrder());
        Element messageG1 = pairing.getG1().newElement().pow(h).getImmutable();

        // Derive GT message via pairing with public key
        Element messageGT = pairing.pairing(messageG1, ibe.getP_pub()).getImmutable();

        // Encrypt messageGT for Bob
        Map<String, Element> ciphertext = alice.encrypt(bob.getId(), messageGT);

        // Bob computes partial keys (choose any 3 of 4 nodes)
        int[] nodes = {1, 2, 4};
        Map<Integer, Element> partials = bob.computePartialKeys(nodes);

        // Bob reconstructs his private key
        Element bobPrivKey = bob.reconstructPrivateKey(partials);

        // Bob decrypts
        Element decrypted = alice.decrypt(bobPrivKey, ciphertext);

        System.out.println("Original message (GT): " + messageGT);
        System.out.println("Decrypted message (GT): " + decrypted);

        assertTrue(messageGT.isEqual(decrypted), "Decrypted message should match original");
    }
}
