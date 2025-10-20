import java.math.BigInteger;
import java.security.SecureRandom;

public class Alice {
    private final Homomorphic.KeyPair keyPair;
    private final SecureRandom rnd = new SecureRandom();

    public Alice(int secretBits) {
        this.keyPair = Homomorphic.genKeyPair(secretBits, rnd);
    }

    public Homomorphic.KeyPair getKeyPair() {
        return keyPair;
    }

    /** Encrypt a single bit (0 or 1) */
    public Homomorphic.Ciphertext encryptBit(int bit) {
        return Homomorphic.encrypt(BigInteger.valueOf(bit), keyPair, rnd);
    }

    /** Encrypt a 3-bit blood type as array [Rh, B, A] */
    public Homomorphic.Ciphertext[] encryptBloodType(int type) {
        Homomorphic.Ciphertext[] c = new Homomorphic.Ciphertext[3];
        for (int i = 0; i < 3; i++) {
            int bit = (type >> i) & 1;
            c[i] = encryptBit(bit);
        }
        return c;
    }

    /** Decrypt a ciphertext to int (0 or 1) */
    public int decrypt(Homomorphic.Ciphertext ct) {
        return Homomorphic.decrypt(ct, keyPair.getPrivate()).intValue();
    }
}
