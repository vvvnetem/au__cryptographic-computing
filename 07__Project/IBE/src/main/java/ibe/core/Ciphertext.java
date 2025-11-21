package ibe.core;

import ibe.core.interfaces.PairingScheme;
import java.io.*;
import java.util.Arrays;

/**
 * Represents an IBE ciphertext: (U, V, W)
 * U is a G1 element, V and W are byte arrays
 */
public class Ciphertext implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] uBytes;  // Serialized U element from G1
    private final byte[] v;       // Masked sigma
    private final byte[] w;       // Masked message

    public Ciphertext(PairingScheme.G1Element u, byte[] v, byte[] w) {
        this.uBytes = u.toBytes();
        this.v = Arrays.copyOf(v, v.length);
        this.w = Arrays.copyOf(w, w.length);
    }

    private Ciphertext(byte[] uBytes, byte[] v, byte[] w) {
        this.uBytes = Arrays.copyOf(uBytes, uBytes.length);
        this.v = Arrays.copyOf(v, v.length);
        this.w = Arrays.copyOf(w, w.length);
    }

    public PairingScheme.G1Element getU(PairingScheme pairing) {
        return pairing.g1FromBytes(uBytes);
    }

    public byte[] getV() {
        return Arrays.copyOf(v, v.length);
    }

    public byte[] getW() {
        return Arrays.copyOf(w, w.length);
    }

    /**
     * Serialize to bytes for transmission
     */
    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Write U length and bytes
        dos.writeInt(uBytes.length);
        dos.write(uBytes);

        // Write V length and bytes
        dos.writeInt(v.length);
        dos.write(v);

        // Write W length and bytes
        dos.writeInt(w.length);
        dos.write(w);

        return baos.toByteArray();
    }

    /**
     * Deserialize from bytes
     */
    public static Ciphertext fromBytes(byte[] bytes) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        DataInputStream dis = new DataInputStream(bais);

        // Read U
        int uLength = dis.readInt();
        byte[] uBytes = new byte[uLength];
        dis.readFully(uBytes);

        // Read V
        int vLength = dis.readInt();
        byte[] v = new byte[vLength];
        dis.readFully(v);

        // Read W
        int wLength = dis.readInt();
        byte[] w = new byte[wLength];
        dis.readFully(w);

        return new Ciphertext(uBytes, v, w);
    }

    /**
     * Save to file
     */
    public void saveToFile(String filename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(toBytes());
        }
    }

    /**
     * Load from file
     */
    public static Ciphertext loadFromFile(String filename) throws IOException {
        try (FileInputStream fis = new FileInputStream(filename)) {
            byte[] bytes = fis.readAllBytes();
            return fromBytes(bytes);
        }
    }

    @Override
    public String toString() {
        return String.format(
                "Ciphertext{U_length=%d, V_length=%d, W_length=%d}",
                uBytes.length, v.length, w.length
        );
    }
}