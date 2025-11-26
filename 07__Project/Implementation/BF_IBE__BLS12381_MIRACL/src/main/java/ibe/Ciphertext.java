package ibe;

import ibe.fourCoreAlg.Setup;
import org.miracl.core.BLS12381.*;

/**
 * Ciphertext structure for BF-IBE
 */
public class Ciphertext {

    /** U = rP ∈ G1 */
    public ECP U;

    /** V = sigma XOR H2(g_ID^r) */
    public byte[] V;

    /** W = M XOR H4(sigma) */
    public byte[] W;

    /** Identity this ciphertext is intended for */
    public String recipientIdentity;

    /** MIRACL BLS12-381 uncompressed G1 point size */
    private static final int G1_UNCOMPRESSED_LEN = 97;  // 1 + 48 + 48

    public Ciphertext() { }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Ciphertext for: ").append(recipientIdentity).append("\n");
        sb.append("U: ").append(U.toString()).append("\n");
        sb.append("V (hex): ").append(Setup.bytesToHex(V)).append("\n");
        sb.append("W (hex): ").append(Setup.bytesToHex(W)).append("\n");
        return sb.toString();
    }

    /**
     * Serialize ciphertext as:
     *   [U_bytes][V_len(4)][V][W_len(4)][W]
     */
    public byte[] toBytes() {
        byte[] uBytes = new byte[G1_UNCOMPRESSED_LEN];
        U.toBytes(uBytes, false); // false = uncompressed

        int total = uBytes.length + 4 + V.length + 4 + W.length;
        byte[] out = new byte[total];
        int pos = 0;

        // U
        System.arraycopy(uBytes, 0, out, pos, uBytes.length);
        pos += uBytes.length;

        // V length
        out[pos++] = (byte)(V.length >>> 24);
        out[pos++] = (byte)(V.length >>> 16);
        out[pos++] = (byte)(V.length >>> 8);
        out[pos++] = (byte)(V.length);

        // V
        System.arraycopy(V, 0, out, pos, V.length);
        pos += V.length;

        // W length
        out[pos++] = (byte)(W.length >>> 24);
        out[pos++] = (byte)(W.length >>> 16);
        out[pos++] = (byte)(W.length >>> 8);
        out[pos++] = (byte)(W.length);

        // W
        System.arraycopy(W, 0, out, pos, W.length);

        return out;
    }

    /**
     * Deserialize ciphertext from bytes
     */
    public static Ciphertext fromBytes(byte[] data, String identity) {
        int pos = 0;

        // U
        byte[] uBytes = new byte[G1_UNCOMPRESSED_LEN];
        System.arraycopy(data, pos, uBytes, 0, G1_UNCOMPRESSED_LEN);
        ECP U = ECP.fromBytes(uBytes);
        pos += G1_UNCOMPRESSED_LEN;

        // V length
        int vLen =
                ((data[pos++] & 0xFF) << 24) |
                        ((data[pos++] & 0xFF) << 16) |
                        ((data[pos++] & 0xFF) <<  8) |
                        ((data[pos++] & 0xFF));

        // V
        byte[] V = new byte[vLen];
        System.arraycopy(data, pos, V, 0, vLen);
        pos += vLen;

        // W length
        int wLen =
                ((data[pos++] & 0xFF) << 24) |
                        ((data[pos++] & 0xFF) << 16) |
                        ((data[pos++] & 0xFF) <<  8) |
                        ((data[pos++] & 0xFF));

        // W
        byte[] W = new byte[wLen];
        System.arraycopy(data, pos, W, 0, wLen);

        Ciphertext C = new Ciphertext();
        C.U = U;
        C.V = V;
        C.W = W;
        C.recipientIdentity = identity;

        return C;
    }
}
