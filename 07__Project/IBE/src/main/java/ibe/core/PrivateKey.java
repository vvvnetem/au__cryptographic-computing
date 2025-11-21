package ibe.core;

import ibe.core.interfaces.PairingScheme;
import java.io.*;

/**
 * User's private key for their identity.
 * This is derived from the master secret and the user's identity.
 */
public class PrivateKey implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String identity;
    private final PairingScheme.G1Element privateKeyElement; // dID = s * QID

    public PrivateKey(String identity, PairingScheme.G1Element privateKeyElement) {
        this.identity = identity;
        this.privateKeyElement = privateKeyElement.duplicate();
    }

    public String getIdentity() {
        return identity;
    }

    public PairingScheme.G1Element getPrivateKeyElement() {
        return privateKeyElement.duplicate();
    }

    /**
     * Serialize to file
     */
    public void saveToFile(String filename) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(filename))) {
            oos.writeObject(this);
        }
    }

    /**
     * Deserialize from file
     */
    public static PrivateKey loadFromFile(String filename)
            throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(filename))) {
            return (PrivateKey) ois.readObject();
        }
    }

    @Override
    public String toString() {
        return String.format("PrivateKey{identity='%s'}", identity);
    }
}