package ibe.crypto;

import ibe.core.Ciphertext;
import ibe.core.SystemParameters;
import ibe.core.interfaces.HashFunction;
import ibe.core.interfaces.PairingScheme;
import ibe.utils.ByteUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * IBE Encryption implementation.
 * Anyone can encrypt a message to a user's identity without needing their private key.
 */
public class IBEEncrypt {

    private static final SecureRandom random = new SecureRandom();

    /**
     * Encrypt a message for a given identity.
     *
     * FullIdent encryption algorithm from the paper:
     * 1. Compute QID = H1(identity)
     * 2. Choose random σ
     * 3. Compute r = H3(σ, M)
     * 4. Compute gID = e(QID, Ppub)
     * 5. Set ciphertext: C = (U, V, W)
     *    U = rP
     *    V = σ ⊕ H2(gID^r)
     *    W = M ⊕ H4(σ)
     *
     * @param params System parameters
     * @param identity Recipient's identity
     * @param message Message to encrypt
     * @return Ciphertext
     */
    public static Ciphertext encrypt(
            SystemParameters params,
            String identity,
            byte[] message) {

        PairingScheme pairing = params.getPairing();
        HashFunction hashFunc = params.getHashFunction();
        int messageLength = params.getMessageLengthBytes();

        // Validate message length
        if (message.length != messageLength) {
            throw new IllegalArgumentException(
                    String.format("Message must be exactly %d bytes, got %d",
                            messageLength, message.length));
        }

        // Step 1: Compute QID = H1(identity)
        PairingScheme.G1Element QID = hashFunc.hashToG1(identity, pairing);

        // Step 2: Choose random σ
        byte[] sigma = new byte[messageLength];
        random.nextBytes(sigma);

        // Step 3: Compute r = H3(σ, M)
        BigInteger r = hashFunc.hashToZq(sigma, message, pairing.getGroupOrder());

        // Step 4: Compute gID = e(QID, Ppub)
        PairingScheme.G1Element Ppub = params.getPublicKey();
        PairingScheme.G2Element gID = pairing.pair(QID, Ppub);

        // Compute gID^r
        PairingScheme.G2Element gID_r = gID.pow(r);

        // Step 5: Create ciphertext components

        // U = rP
        PairingScheme.G1Element P = params.getGenerator();
        PairingScheme.G1Element U = P.multiply(r);

        // V = σ ⊕ H2(gID^r)
        byte[] h2_result = hashFunc.hashToBytes(gID_r, messageLength);
        byte[] V = ByteUtils.xor(sigma, h2_result);

        // W = M ⊕ H4(σ)
        byte[] h4_result = hashFunc.hashToBytes(sigma, messageLength);
        byte[] W = ByteUtils.xor(message, h4_result);

        return new Ciphertext(U, V, W);
    }
}