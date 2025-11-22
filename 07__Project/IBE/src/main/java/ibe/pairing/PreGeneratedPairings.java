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
     * Type F pairing parameters (in hexadecimal) for BLS12-381.
     * For quick test purpose. jPBC is not suited for BLS curves.
     * Apache Milagro (AMCL) has hash_to_curve() according to RFC9830
     -------------------------------------------------------------
         "type f\n" +
            "q 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab\n" +
            "r 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001\n" +
            "h 0x1\n" +
            "b 0x4\n" +
            "nqr 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa\n" +
            "c0 0x1\n" +
            "c1  0x1\n" +
            "twist_type m\n" +
            "bt_c0 0x4\n" +
            "bt_c1 0x4\n" +
            "g1_x 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\n" +
            "g1_y 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1\n" +
            "g2_x1 0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8\n" +
            "g2_x0 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e\n" +
            "g2_y1 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801\n" +
            "g2_y0 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be\n" +
            "x 0xd201000000010000\n" +
            "sign -1\n"
     */

    
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
