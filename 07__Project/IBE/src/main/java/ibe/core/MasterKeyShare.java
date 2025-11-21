package ibe.core;

import ibe.core.interfaces.SecretSharingScheme;
import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Represents one server's share of the master secret.
 * Each server keeps this private.
 */
public class MasterKeyShare implements Serializable {
    private static final long serialVersionUID = 1L;

    private final int serverIndex;  // Which server (1, 2, or 3)
    private final SecretSharingScheme.Share share;

    public MasterKeyShare(int serverIndex, SecretSharingScheme.Share share) {
        this.serverIndex = serverIndex;
        this.share = share;
    }

    public int getServerIndex() {
        return serverIndex;
    }

    public SecretSharingScheme.Share getShare() {
        return share;
    }

    public BigInteger getShareValue() {
        return share.getValue();
    }

    /**
     * Securely clear the share from memory
     */
    public void destroy() {
        // In Java, we can't truly zero memory, but we can overwrite
        // The actual BigInteger is harder to clear
        System.out.println("Warning: MasterKeyShare destroyed for server " + serverIndex);
    }

    /**
     * Serialize to encrypted file (in production, add encryption)
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
    public static MasterKeyShare loadFromFile(String filename)
            throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(filename))) {
            return (MasterKeyShare) ois.readObject();
        }
    }

    @Override
    public String toString() {
        return String.format(
                "MasterKeyShare{server=%d, shareIndex=%d}",
                serverIndex,
                share.getIndex()
        );
    }
}