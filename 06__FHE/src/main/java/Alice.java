import java.util.Objects;

/**
 * Alice: generates Paillier keys, encrypts her recipient bits and a small
 * collection of precomputed encrypted masks that Bob will need.
 *
 * Alice sends the payload (all ciphertexts) to Bob.
 */
public class Alice {
    private final Paillier.KeyPair kp;

    public Alice(int keyBits) {
        this.kp = Paillier.keyGen(keyBits);
    }

    public Paillier.KeyPair getKeyPair() { return kp; }

    // encrypt a single bit (0/1)
    public Paillier.Ciphertext encryptBit(int bit) {
        return Paillier.encryptInt(bit, kp.getPublic());
    }

    // Prepare and return a payload containing all encrypted recipient values Bob needs.
    // recipient is index 0..7 (bits as LSB-first: bit0=Rh, bit1=B, bit2=A)
    public RecipientPayload prepareRecipientPayload(int recipientIndex) {
        int r0 = (recipientIndex >> 0) & 1; // Rh
        int r1 = (recipientIndex >> 1) & 1; // B
        int r2 = (recipientIndex >> 2) & 1; // A

        // Basic encrypted bits
        Paillier.Ciphertext encRh = encryptBit(r0);
        Paillier.Ciphertext encB  = encryptBit(r1);
        Paillier.Ciphertext encA  = encryptBit(r2);
        Paillier.Ciphertext encOne = encryptBit(1);
        Paillier.Ciphertext encZero = encryptBit(0);

        // Derived plaintexts Alice can compute
        int rAB = (r2 & r1);              // A & B
        int rA_rh = (r2 & r0);            // A & Rh
        int rB_rh = (r1 & r0);            // B & Rh
        int rAB_rh = (rAB & r0);          // AB & Rh

        Paillier.Ciphertext encAB     = encryptBit(rAB);
        Paillier.Ciphertext encA_rh   = encryptBit(rA_rh);
        Paillier.Ciphertext encB_rh   = encryptBit(rB_rh);
        Paillier.Ciphertext encAB_rh  = encryptBit(rAB_rh);

        return new RecipientPayload(
                encOne, encZero,
                encA, encB, encAB,
                encRh, encA_rh, encB_rh, encAB_rh
        );
    }

    // Small container class with all ciphertexts Bob needs
    public static final class RecipientPayload {
        public final Paillier.Ciphertext encOne;
        public final Paillier.Ciphertext encZero;
        public final Paillier.Ciphertext encA;
        public final Paillier.Ciphertext encB;
        public final Paillier.Ciphertext encAB;
        public final Paillier.Ciphertext encRh;
        public final Paillier.Ciphertext encA_rh;
        public final Paillier.Ciphertext encB_rh;
        public final Paillier.Ciphertext encAB_rh;

        public RecipientPayload(Paillier.Ciphertext encOne, Paillier.Ciphertext encZero,
                                Paillier.Ciphertext encA, Paillier.Ciphertext encB, Paillier.Ciphertext encAB,
                                Paillier.Ciphertext encRh, Paillier.Ciphertext encA_rh, Paillier.Ciphertext encB_rh, Paillier.Ciphertext encAB_rh) {
            this.encOne = Objects.requireNonNull(encOne);
            this.encZero = Objects.requireNonNull(encZero);
            this.encA = encA; this.encB = encB; this.encAB = encAB;
            this.encRh = encRh; this.encA_rh = encA_rh; this.encB_rh = encB_rh; this.encAB_rh = encAB_rh;
        }
    }

    // Alice decrypts final result (single ciphertext -> int 0/1)
    public int decrypt(Paillier.Ciphertext ct) {
        return Paillier.decrypt(ct, kp).intValue();
    }
}
