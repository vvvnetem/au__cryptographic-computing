package crypto;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class BF_IBE {

    private Pairing pairing;
    private Element g;       // G1 generator
    private Element g2;      // G2 generator
    private Element P_pub;   // Public key in G2
    private BigInteger MSK;
    private Random random = new Random();

    public BF_IBE(BigInteger msk, String curve) {
        this.MSK = msk;
        pairing = PairingFactory.getPairing("jars/jpbc/params/curves/" + curve + ".properties");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);

        // Generators
        g = pairing.getG1().newRandomElement().getImmutable();
        g2 = pairing.getG2().newRandomElement().getImmutable();

        // Public key in G2
        P_pub = g2.pow(MSK).getImmutable();
    }

    /** Hash identity string to a G1 element */
    public Element H1(String id) {
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        return pairing.getG1().newElement().setFromHash(idBytes, 0, idBytes.length).getImmutable();
    }

    /** Extract user private key (for identity), returns element in G2 */
    public Element extractPrivateKey(BigInteger share, String id) {
        return g2.pow(share).getImmutable();
    }

    /** Combine partial keys (threshold) into full private key in G2 */
    public Element combinePartialKeys(Map<Integer, Element> partials, BigInteger prime) {
        Element d_ID = pairing.getG2().newZeroElement().getImmutable();
        for (int i : partials.keySet()) {
            BigInteger li = BigInteger.ONE;
            for (int j : partials.keySet()) {
                if (i != j) {
                    BigInteger numerator = BigInteger.valueOf(j);
                    BigInteger denominator = BigInteger.valueOf(j).subtract(BigInteger.valueOf(i));
                    li = li.multiply(numerator.multiply(denominator.modInverse(prime))).mod(prime);
                }
            }
            Element term = partials.get(i).duplicate().pow(li).getImmutable();
            d_ID = d_ID.duplicate().mul(term).getImmutable();
        }
        return d_ID;
    }

    /** Encrypt a plaintext string for a given identity */
    public Map<String, Element> encrypt(String id, String plaintext) {
        byte[] msgBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        BigInteger msgInt = new BigInteger(1, msgBytes);

        // Map message to GT: M = e(g, g2)^msgInt
        Element M_GT = pairing.pairing(g, g2).pow(msgInt).getImmutable();

        Element Q_id = H1(id);  // G1
        BigInteger r = new BigInteger(pairing.getZr().getLengthInBytes() * 8, random)
                .mod(pairing.getZr().getOrder());

        Element U = g.pow(r).getImmutable();                 // G1
        Element V = M_GT.duplicate().add(pairing.pairing(Q_id, P_pub).pow(r)).getImmutable();  // GT

        Map<String, Element> ct = new HashMap<>();
        ct.put("U", U);
        ct.put("V", V);
        return ct;
    }

    /** Decrypt using recipient private key d_ID */
    public String decrypt(Element d_ID, Map<String, Element> ct) {
        Element U = ct.get("U");
        Element V = ct.get("V");

        // Compute shared GT key
        Element K = pairing.pairing(U, d_ID).getImmutable();
        Element M_GT = V.duplicate().sub(K);

        // Recover message from GT exponent
        BigInteger recovered = M_GT.toBigInteger().mod(pairing.getZr().getOrder());
        byte[] msgBytes = recovered.toByteArray();

        return new String(msgBytes, StandardCharsets.UTF_8);
    }

    // Getters
    public Pairing getPairing() { return pairing; }
    public Element getP_pub() { return P_pub; }
    public Element getG1() { return g; }
    public Element getG2() { return g2; }
}
