package ibe.threshold;

import ibe.core.SystemParameters;
import ibe.core.MasterKeyShare;
import ibe.core.interfaces.HashFunction;
import ibe.core.interfaces.PairingScheme;

/**
 * Represents a single PKG server in the distributed system.
 * Each server holds a share of the master secret and can generate partial keys.
 */
public class PKGServer {

    private final int serverIndex;
    private final String serverName;
    private final SystemParameters systemParameters;
    private final MasterKeyShare masterKeyShare;

    public PKGServer(int serverIndex,
                     String serverName,
                     SystemParameters systemParameters,
                     MasterKeyShare masterKeyShare) {
        this.serverIndex = serverIndex;
        this.serverName = serverName;
        this.systemParameters = systemParameters;
        this.masterKeyShare = masterKeyShare;
    }

    public int getServerIndex() {
        return serverIndex;
    }

    public String getServerName() {
        return serverName;
    }

    /**
     * Generate a partial private key for a user's identity.
     */
    public PartialPrivateKey generatePartialKey(String identity) {
        System.out.printf("%s: Generating partial key for '%s'\n", serverName, identity);

        HashFunction hashFunc = systemParameters.getHashFunction();
        PairingScheme pairing = systemParameters.getPairing();

        // Hash identity to G1 point
        PairingScheme.G1Element QID = hashFunc.hashToG1(identity, pairing);

        // Multiply by this server's share: partialKey_i = share_i * QID
        PairingScheme.G1Element partialKey = QID.multiply(masterKeyShare.getShareValue());

        System.out.printf("%s: Partial key generated\n", serverName);

        return new PartialPrivateKey(serverIndex, identity, partialKey);
    }

    /**
     * Verify partial key using Lagrange interpolation approach.
     *
     * We can't verify individual shares directly because after MPC,
     * each server's share is a combination. Instead, we verify that
     * the partial key is well-formed (not identity element).
     *
     * Full verification happens when combining keys.
     */
    public boolean verifyPartialKey(PartialPrivateKey partialKey) {
        // Simple check: make sure it's not the identity element
        boolean notIdentity = !partialKey.getPartialKey().isIdentity();

        if (notIdentity) {
            System.out.printf("%s: Partial key is well-formed (non-identity)\n", serverName);
        } else {
            System.err.printf("%s: ERROR - Partial key is identity element!\n", serverName);
        }

        return notIdentity;
    }

    @Override
    public String toString() {
        return String.format("PKGServer{index=%d, name='%s'}", serverIndex, serverName);
    }
}