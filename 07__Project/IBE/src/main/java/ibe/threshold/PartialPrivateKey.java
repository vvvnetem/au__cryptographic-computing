package ibe.threshold;

import ibe.core.interfaces.PairingScheme;
import java.io.Serializable;

/**
 * Represents a partial private key from one server.
 * Bob receives these from multiple servers and combines them.
 */
public class PartialPrivateKey implements Serializable {
    private static final long serialVersionUID = 1L;

    private final int serverIndex;
    private final String identity;
    private final PairingScheme.G1Element partialKey;

    public PartialPrivateKey(int serverIndex, String identity, PairingScheme.G1Element partialKey) {
        this.serverIndex = serverIndex;
        this.identity = identity;
        this.partialKey = partialKey.duplicate();
    }

    public int getServerIndex() {
        return serverIndex;
    }

    public String getIdentity() {
        return identity;
    }

    public PairingScheme.G1Element getPartialKey() {
        return partialKey.duplicate();
    }

    @Override
    public String toString() {
        return String.format("PartialPrivateKey{server=%d, identity='%s'}",
                serverIndex, identity);
    }
}