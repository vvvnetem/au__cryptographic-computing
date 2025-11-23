package ibe;

import ibe.fourCoreAlg.Setup;
import org.apache.milagro.amcl.BLS381.*;

/**
 * Ciphertext class
 * Contains the encrypted message
 */
public class Ciphertext {
    // U = r*P in G1
    public ECP U;

    // V = sigma XOR H2(g_ID^r)
    public byte[] V;

    // W = M XOR H4(sigma)
    public byte[] W;

    // Store the recipient identity for reference
    public String recipientIdentity;

    public Ciphertext() {
        // Constructor
    }

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
     * Serialize ciphertext to bytes for transmission
     */
    public byte[] toBytes() {
        // Format: [U_bytes][V_length][V][W_length][W]
        byte[] uBytes = new byte[2 * BIG.MODBYTES + 1];
        U.toBytes(uBytes, false); // uncompressed format

        int totalLength = uBytes.length + 4 + V.length + 4 + W.length;
        byte[] result = new byte[totalLength];

        int offset = 0;

        // Copy U
        System.arraycopy(uBytes, 0, result, offset, uBytes.length);
        offset += uBytes.length;

        // Copy V length (4 bytes)
        result[offset++] = (byte) (V.length >> 24);
        result[offset++] = (byte) (V.length >> 16);
        result[offset++] = (byte) (V.length >> 8);
        result[offset++] = (byte) V.length;

        // Copy V
        System.arraycopy(V, 0, result, offset, V.length);
        offset += V.length;

        // Copy W length (4 bytes)
        result[offset++] = (byte) (W.length >> 24);
        result[offset++] = (byte) (W.length >> 16);
        result[offset++] = (byte) (W.length >> 8);
        result[offset++] = (byte) W.length;

        // Copy W
        System.arraycopy(W, 0, result, offset, W.length);

        return result;
    }

    /**
     * Deserialize ciphertext from bytes
     */
    public static Ciphertext fromBytes(byte[] bytes, String recipientIdentity) {
        int offset = 0;

        // Read U
        int uLen = 2 * BIG.MODBYTES + 1;
        byte[] uBytes = new byte[uLen];
        System.arraycopy(bytes, offset, uBytes, 0, uLen);
        ECP U = ECP.fromBytes(uBytes);
        offset += uLen;

        // Read V length
        int vLen = ((bytes[offset++] & 0xFF) << 24) |
                ((bytes[offset++] & 0xFF) << 16) |
                ((bytes[offset++] & 0xFF) << 8) |
                (bytes[offset++] & 0xFF);

        // Read V
        byte[] V = new byte[vLen];
        System.arraycopy(bytes, offset, V, 0, vLen);
        offset += vLen;

        // Read W length
        int wLen = ((bytes[offset++] & 0xFF) << 24) |
                ((bytes[offset++] & 0xFF) << 16) |
                ((bytes[offset++] & 0xFF) << 8) |
                (bytes[offset++] & 0xFF);

        // Read W
        byte[] W = new byte[wLen];
        System.arraycopy(bytes, offset, W, 0, wLen);

        Ciphertext ciphertext = new Ciphertext();
        ciphertext.U = U;
        ciphertext.V = V;
        ciphertext.W = W;
        ciphertext.recipientIdentity = recipientIdentity;

        return ciphertext;
    }
}
