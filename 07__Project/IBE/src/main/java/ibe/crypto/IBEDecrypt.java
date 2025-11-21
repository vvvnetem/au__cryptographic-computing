package ibe.crypto;

import ibe.core.Ciphertext;
import ibe.core.PrivateKey;
import ibe.core.SystemParameters;
import ibe.core.interfaces.HashFunction;
import ibe.core.interfaces.PairingScheme;
import ibe.utils.ByteUtils;

import java.math.BigInteger;

/**
 * IBE Decryption implementation.
 * Users can decrypt messages sent to their identity using their private key.
 */
public class IBEDecrypt {

    /**
     * Decrypt a ciphertext using the recipient's private key.
     *
     * FullIdent decryption algorithm from the paper:
     * 1. Compute σ = V ⊕ H2(e(dID, U))
     * 2. Compute M = W ⊕ H4(σ)
     * 3. Verify: compute r = H3(σ, M) and check U = rP
     * 4. If verification passes, return M; otherwise reject
     *
     * @param params System parameters
     * @param privateKey Recipient's private key
     * @param ciphertext Ciphertext to decrypt
     * @return Decrypted message
     * @throws SecurityException if verification fails
     */
    public static byte[] decrypt(
            SystemParameters params,
            PrivateKey privateKey,
            Ciphertext ciphertext) {

        PairingScheme pairing = params.getPairing();
        HashFunction hashFunc = params.getHashFunction();
        int messageLength = params.getMessageLengthBytes();

        // Get ciphertext components
        PairingScheme.G1Element U = ciphertext.getU(pairing);
        byte[] V = ciphertext.getV();
        byte[] W = ciphertext.getW();

        // Verify U is not identity element
        if (U.isIdentity()) {
            throw new SecurityException("Invalid ciphertext: U is identity element");
        }

        // Step 1: Compute σ = V ⊕ H2(e(dID, U))
        PairingScheme.G1Element dID = privateKey.getPrivateKeyElement();
        PairingScheme.G2Element pairing_result = pairing.pair(dID, U);

        byte[] h2_result = hashFunc.hashToBytes(pairing_result, messageLength);
        byte[] sigma = ByteUtils.xor(V, h2_result);

        // Step 2: Compute M = W ⊕ H4(σ)
        byte[] h4_result = hashFunc.hashToBytes(sigma, messageLength);
        byte[] M = ByteUtils.xor(W, h4_result);

        // Step 3: Verification - recompute r and check U = rP
        BigInteger r = hashFunc.hashToZq(sigma, M, pairing.getGroupOrder());
        PairingScheme.G1Element P = params.getGenerator();
        PairingScheme.G1Element U_check = P.multiply(r);

        if (!U_check.equals(U)) {
            throw new SecurityException("Ciphertext verification failed! Message may be tampered.");
        }

        return M;
    }
}