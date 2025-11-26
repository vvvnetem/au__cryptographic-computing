package ibe.fourCoreAlg;

import ibe.Ciphertext;
import org.miracl.core.BLS12381.*;
import org.miracl.core.HASH256;

import java.security.SecureRandom;

import static ibe.fourCoreAlg.Setup.*;

public class Encrypt {

    /**
     * Encrypt Algorithm — MIRACL-CORE version
     */
    public static Ciphertext encrypt(byte[] message, String identity, SystemParams params) {
        System.out.println("\n=== Encrypt Algorithm ===");
        System.out.println("Encrypting for: " + identity);

        // Step 1: Compute Q_ID = H1(ID)
        ECP Q_ID = hashToG1(identity);

        // Step 2: Choose random σ
        byte[] sigma = new byte[params.messageLength];
        new SecureRandom().nextBytes(sigma);

        // Step 3: Compute r = H3(σ || M)
        BIG r = hashToZq(sigma, message, params.q);

        // Step 4: U = r * P
        ECP U = PAIR.G1mul(params.P, r);

        // Step 5: Compute base pairing e(Q_pub, Q_ID)
        FP12 base = PAIR.fexp(PAIR.ate(params.Q_pub, Q_ID));

        // Step 6: Derive scalar from U
        byte[] U_bytes = new byte[1 + 2 * FIELD_BYTES];
        U.toBytes(U_bytes, false);

        HASH256 sha = new HASH256();
        sha.process_array(U_bytes);
        byte[] hash = sha.hash();

        // Pad or truncate hash to FIELD_BYTES
        byte[] scalarBytes = new byte[FIELD_BYTES];
        int copyLen = Math.min(hash.length, FIELD_BYTES);
        System.arraycopy(hash, 0, scalarBytes, FIELD_BYTES - copyLen, copyLen);

        BIG scalar = BIG.fromBytes(scalarBytes);
        scalar.mod(params.q);
        if (scalar.iszilch()) scalar.inc(1);

        // Step 7: Compute mask = base^scalar
        FP12 mask = PAIR.GTpow(base, scalar);

        // Step 8: V = σ XOR H2(mask)
        byte[] V = xorBytes(sigma, hashFromGT(mask, params.messageLength));

        // Step 9: W = M XOR H4(σ)
        byte[] W = xorBytes(message, hashToBytes(sigma, message.length));

        // Step 10: Construct ciphertext
        Ciphertext C = new Ciphertext();
        C.U = U;
        C.V = V;
        C.W = W;
        C.recipientIdentity = identity;

        System.out.println("Encryption complete ✓");
        return C;
    }

    // ------------------------------------------------------------------------
    // Utility: XOR two byte arrays
    // ------------------------------------------------------------------------
    static byte[] xorBytes(byte[] a, byte[] b) {
        if (a.length != b.length)
            throw new IllegalArgumentException("XOR length mismatch");
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++)
            r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    /** Convenience wrapper: encrypt string messages */
    public static Ciphertext encrypt(String message, String identity, SystemParams params) {
        return encrypt(message.getBytes(), identity, params);
    }

    /** Quick test */
    public static void main(String[] args) {
        System.out.println("=== TESTING ENCRYPT ALGORITHM ===");

        Object[] setupResult = Setup.setup(128);
        SystemParams params = (SystemParams) setupResult[0];
        MasterKey master = (MasterKey) setupResult[1];

        String bobID = "bob@company.com";

        // Encrypt a test message
        String msg = "Hello Bob! This is a test message.";
        Ciphertext C = encrypt(msg.getBytes(), bobID, params);

        System.out.println("\nCiphertext components:");
        System.out.println("U: " + C.U.toString());
        System.out.println("V (hex): " + bytesToHex(C.V));
        System.out.println("W (hex): " + bytesToHex(C.W));
        System.out.println("Recipient: " + C.recipientIdentity);
    }
}
