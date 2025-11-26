package ibe.fourCoreAlg;

import ibe.Ciphertext;
import org.miracl.core.BLS12381.*;
import org.miracl.core.HASH256;

import java.util.Arrays;
import static ibe.fourCoreAlg.Setup.*;
import static ibe.fourCoreAlg.Encrypt.xorBytes;
import static ibe.fourCoreAlg.Extract.extract;

public class Decrypt {

    /**
     * Decrypt Algorithm (MIRACL-CORE version)
     */
    public static byte[] decrypt(Ciphertext ciphertext, Extract.PrivateKey privateKey, SystemParams params) {
        System.out.println("\n=== Decrypt Algorithm ===");
        System.out.println("Decrypting for: " + privateKey.identity);

        if (ciphertext.U.is_infinity()) {
            System.out.println("Error: Invalid ciphertext (U is infinity)");
            return null;
        }

        // Step 1: Compute base pairing e(Q, d_ID)
        FP12 base = PAIR.fexp(PAIR.ate(params.Q, privateKey.d_ID));

        // Step 2: Derive exponent from U
        byte[] U_bytes = new byte[1 + 2 * FIELD_BYTES];
        ciphertext.U.toBytes(U_bytes, false);

        HASH256 sha = new HASH256();
        sha.process_array(U_bytes);
        byte[] h = sha.hash();

        // Pad/truncate hash to FIELD_BYTES
        byte[] scalarBytes = new byte[FIELD_BYTES];
        int copyLen = Math.min(h.length, FIELD_BYTES);
        System.arraycopy(h, 0, scalarBytes, FIELD_BYTES - copyLen, copyLen);

        BIG r_U = BIG.fromBytes(scalarBytes);
        r_U.mod(params.q);
        if (r_U.iszilch()) r_U.inc(1);

        // Step 3: Compute mask = base^r_U
        FP12 mask = PAIR.GTpow(base, r_U);

        // Step 4: Recover sigma
        byte[] sigma = xorBytes(ciphertext.V, hashFromGT(mask, params.messageLength));

        // Step 5: Recover M
        byte[] M = xorBytes(ciphertext.W, hashToBytes(sigma, ciphertext.W.length));

        // Step 6: Verify U = r*P
        BIG r_expected = hashToZq(sigma, M, params.q);
        ECP expected_U = PAIR.G1mul(params.P, r_expected);

        if (!expected_U.equals(ciphertext.U)) {
            System.out.println("Error: Verification failed — ciphertext tampered");
            return null;
        }

        System.out.println("Decryption successful ✓");
        return M;
    }

    /** Convenience wrapper: return decrypted message as string */
    public static String decryptToString(Ciphertext ciphertext, Extract.PrivateKey privateKey, SystemParams params) {
        byte[] out = decrypt(ciphertext, privateKey, params);
        return (out == null) ? null : new String(out);
    }

    /** Quick test */
    public static void main(String[] args) {
        System.out.println("=== TESTING DECRYPT ALGORITHM (MIRACL-CORE) ===");

        Object[] result = Setup.setup(128);
        SystemParams params = (SystemParams) result[0];
        MasterKey master = (MasterKey) result[1];

        String bob = "bob@company.com";
        String alice = "alice@company.com";

        Extract.PrivateKey bobKey = extract(bob, master, params);
        Extract.PrivateKey aliceKey = extract(alice, master, params);

        // ----------------------------
        System.out.println("\nTest 1: Basic Decryption");
        System.out.println("=".repeat(50));
        String msg1 = "Hello Bob!";
        Ciphertext C1 = Encrypt.encrypt(msg1.getBytes(), bob, params);

        byte[] dec1 = decrypt(C1, bobKey, params);
        boolean pass1 = dec1 != null && Arrays.equals(dec1, msg1.getBytes());
        System.out.println("Decrypted message: " + (dec1 != null ? new String(dec1) : "null"));
        System.out.println("Test 1: " + (pass1 ? "✓ PASS" : "✗ FAIL"));

        // ----------------------------
        System.out.println("\nTest 2: Wrong Key Rejection");
        System.out.println("=".repeat(50));
        String msg2 = "Secret for Bob";
        Ciphertext C2 = Encrypt.encrypt(msg2.getBytes(), bob, params);

        byte[] wrong = decrypt(C2, aliceKey, params);
        byte[] right = decrypt(C2, bobKey, params);
        boolean pass2 = (wrong == null) && right != null && Arrays.equals(right, msg2.getBytes());
        System.out.println("Decryption with Alice's key: " + (wrong != null ? new String(wrong) : "null"));
        System.out.println("Decryption with Bob's key: " + new String(right));
        System.out.println("Test 2: " + (pass2 ? "✓ PASS" : "✗ FAIL"));
    }
}
