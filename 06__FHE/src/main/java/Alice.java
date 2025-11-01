import java.security.SecureRandom;

/**
 * Alice: generates keys and encrypts her recipient bits (3 bits).
 * She chooses subset size sSize for encrypting each bit (controls noise).
 */
public class Alice {
    private final DHE.KeyPair kp;
    private final SecureRandom rnd = new SecureRandom();
    private final int sSize; // subset size used for encryption

    private static final boolean DEBUG = true;  // Add debug flag

    /**
     * Construct Alice and generate keys.
     * We pick parameters that allow depth-3 circuits (example choice).
     */
    public Alice() {
        // Parameter choices (tuned for modest demo):
        // pBits ~ 512, qBits ~ 128, rBits ~ 20, n ~ 1024
        int pBits = 1024; // Noise miatt A-, AB- 0 instead of 1.; 512 -> 1024
        int qBits = 128;
        int rBits = 16; // r_i \approx  2^20; to be between 16 and 32
        int numPublicElements = 1024;
        this.kp = DHE.keyGen(pBits, qBits, rBits, numPublicElements, rnd);

        // subset size for encryption: small-ish to keep noise small but enough for security
        this.sSize = Math.max(8, numPublicElements / 16); // e.g., n/16 ~ 64
    }

    public DHE.KeyPair getKeyPair() { return kp; }

    /** Encrypt a single bit (0/1) using chosen subset size. */
    public DHE.Ciphertext encryptBit(int bit) {
        DHE.Ciphertext ct = DHE.encryptBit(bit, kp.getPublic(), rnd, sSize);
        if (DEBUG) {
            System.out.printf(
                    "[Alice] Encrypt bit=%d | subsetSize=%d | initialNoise≈%d | level=%d%n",
                    bit, sSize, ct.noiseBound, ct.level
            );
        }
        return ct;
    }

    /** Encrypt the 3-bit blood type (LSB first): bit0=Rh, bit1=B, bit2=A */
    public DHE.Ciphertext[] encryptBloodType(int type) {
        DHE.Ciphertext[] c = new DHE.Ciphertext[3];
        for (int i = 0; i < 3; i++) {
            int bit = (type >> i) & 1;
            c[i] = encryptBit(bit);
        }
        return c;
    }

    /** Decrypt single ciphertext to 0/1. */
    public int decrypt(DHE.Ciphertext ct) {
        int result = DHE.decrypt(ct, kp.getPrivate());
        if (DEBUG) {
            System.out.printf("[Alice] Decrypt result = %d%n", result);
        }
        return result;
    }
    /** Recipient payload: simply the encrypted bits (we send all three ciphertexts). */
    public static final class RecipientPayload {
        public final DHE.Ciphertext encRh;
        public final DHE.Ciphertext encB;
        public final DHE.Ciphertext encA;
        public RecipientPayload(DHE.Ciphertext encRh, DHE.Ciphertext encB, DHE.Ciphertext encA) {
            this.encRh = encRh; this.encB = encB; this.encA = encA;
        }
    }

    /** Prepare the small payload to send to Bob (encrypts each recipient bit). */
    public RecipientPayload prepareRecipientPayload(int recipientIndex) {
        DHE.Ciphertext encRh = encryptBit((recipientIndex >> 0) & 1);
        DHE.Ciphertext encB  = encryptBit((recipientIndex >> 1) & 1);
        DHE.Ciphertext encA  = encryptBit((recipientIndex >> 2) & 1);
        return new RecipientPayload(encRh, encB, encA);
    }

}
