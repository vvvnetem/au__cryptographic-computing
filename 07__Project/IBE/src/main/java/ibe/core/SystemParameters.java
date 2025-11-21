package ibe.core;

import ibe.core.interfaces.PairingScheme;
import ibe.core.interfaces.HashFunction;
import java.io.*;

/**
 * Public system parameters that are shared with all parties.
 * These can be published and don't need to be kept secret.
 */
public class SystemParameters implements Serializable {
    private static final long serialVersionUID = 1L;

    private final PairingScheme pairing;
    private final HashFunction hashFunction;
    private final PairingScheme.G1Element generator;      // P
    private final PairingScheme.G1Element publicKey;      // Ppub = s*P
    private final int messageLengthBits;                   // n

    // For threshold: store public commitments of each server
    private final PairingScheme.G1Element[] publicCommitments;
    private final int threshold;  // t
    private final int totalServers; // n

    public SystemParameters(
            PairingScheme pairing,
            HashFunction hashFunction,
            PairingScheme.G1Element generator,
            PairingScheme.G1Element publicKey,
            int messageLengthBits,
            PairingScheme.G1Element[] publicCommitments,
            int threshold,
            int totalServers) {

        this.pairing = pairing;
        this.hashFunction = hashFunction;
        this.generator = generator.duplicate();
        this.publicKey = publicKey.duplicate();
        this.messageLengthBits = messageLengthBits;
        this.publicCommitments = new PairingScheme.G1Element[publicCommitments.length];
        for (int i = 0; i < publicCommitments.length; i++) {
            this.publicCommitments[i] = publicCommitments[i].duplicate();
        }
        this.threshold = threshold;
        this.totalServers = totalServers;
    }

    // Getters
    public PairingScheme getPairing() { return pairing; }
    public HashFunction getHashFunction() { return hashFunction; }
    public PairingScheme.G1Element getGenerator() { return generator.duplicate(); }
    public PairingScheme.G1Element getPublicKey() { return publicKey.duplicate(); }
    public int getMessageLengthBits() { return messageLengthBits; }
    public int getMessageLengthBytes() { return messageLengthBits / 8; }
    public PairingScheme.G1Element getPublicCommitment(int serverIndex) {
        return publicCommitments[serverIndex].duplicate();
    }
    public int getThreshold() { return threshold; }
    public int getTotalServers() { return totalServers; }

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
    public static SystemParameters loadFromFile(String filename)
            throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(filename))) {
            return (SystemParameters) ois.readObject();
        }
    }

    @Override
    public String toString() {
        return String.format(
                "SystemParameters{\n" +
                        "  Pairing: %s\n" +
                        "  Hash: %s\n" +
                        "  Message length: %d bits\n" +
                        "  Threshold: %d out of %d\n" +
                        "}",
                pairing.getName(),
                hashFunction.getName(),
                messageLengthBits,
                threshold,
                totalServers
        );
    }
}