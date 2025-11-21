package ibe.pairing;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

import java.io.ByteArrayInputStream;

/**
 * Pre-generated pairing parameters for quick testing
 */
public class PreGeneratedPairings {

    /**
     * Type A pairing parameters (160-bit r, 512-bit q)
     * Pre-generated for quick initialization
     */
    public static final String TYPE_A_PARAMS =
            "type a\n" +
                    "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n" +
                    "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n" +
                    "r 730750818665451621361119245571504901405976559617\n" +
                    "exp2 159\n" +
                    "exp1 107\n" +
                    "sign1 1\n" +
                    "sign0 1\n";

    /**
     * Create pairing from pre-generated Type A parameters
     */
    public static JPBCPairingScheme createTypeAPairing() {
        System.out.println("Loading pre-generated Type A pairing parameters...");

        // Load parameters from string using ByteArrayInputStream
        ByteArrayInputStream bais = new ByteArrayInputStream(TYPE_A_PARAMS.getBytes());
        PairingParameters params = new PropertiesParameters().load(bais);

        // Create pairing from parameters
        Pairing pairing = PairingFactory.getPairing(params);

        System.out.println("Pairing loaded successfully");
        return new JPBCPairingScheme(pairing, TYPE_A_PARAMS);
    }

    /**
     * Quick pairing for testing (uses pre-generated parameters)
     */
    public static JPBCPairingScheme createQuickPairing() {
        return createTypeAPairing();
    }
}