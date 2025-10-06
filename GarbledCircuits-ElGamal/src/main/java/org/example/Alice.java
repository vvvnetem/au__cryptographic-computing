package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class Alice {
    private ElGamal elGamal;
    private ElGamal.SecretKey[] secretKeys;  // One secret key per OT instance (per input bit)
    private int n; // input size (number of input bits)
    private SecureRandom random = new SecureRandom();

    // Alice's input bits
    private boolean[] x;

    public Alice(boolean[] inputBits, ElGamal elGamal) {
        this.x = Arrays.copyOf(inputBits, inputBits.length);
        this.n = inputBits.length;
        this.elGamal = elGamal;
        this.secretKeys = new ElGamal.SecretKey[n];
    }

    /**
     * Alice generates an ElGamal keypair for each OT instance (for each input bit).
     * Returns the array of public keys corresponding to the n input bits.
     */
    public ElGamal.PublicKey[] generateOTReceiverPublicKeys() {
        ElGamal.PublicKey[] otPublicKeys = new ElGamal.PublicKey[n];
        for (int i = 0; i < n; i++) {
            ElGamal.KeyPair keyPair = elGamal.generateKeyPair();
            otPublicKeys[i] = keyPair.getPublicKey();
            secretKeys[i] = keyPair.getSecretKey();
        }
        return otPublicKeys;
    }

    /**
     *
     * Functions as Receiver for 1-out-of-2 OT to obtain garbled input keys from Bob.
     * Bob provides pairs of encrypted keys for each input bit.
     * Alice inputs her choice bits and gets corresponding key for each OT.
     During the evaluation, the circuit evaluator has only two of the
     input keys (one for each wire) and needs to find the key corresponding
     L(i) to the output wire for the right value.
     e.g: Bob knows that K^{L(i)} = K^{L(i)}_a for a \in {0,1} but
     does not know the value of a.
     But still needs to be able to compute the output key:
     K^i_c, where c = \neg ab.
     */
    public byte[][] receiveGarbledInputKeys(
            ElGamal.Ciphertext[][] otCiphertextsForBit) throws Exception {

        if (otCiphertextsForBit.length != n) {
            throw new IllegalArgumentException("Mismatch in OT ciphertexts length");
        }
        byte[][] garbledInputKeys = new byte[n][]; // 128-bit keys as labels per input bit

        for (int i = 0; i < n; i++) {
            int choiceBit = x[i] ? 1 : 0;
            // Select the ciphertext corresponding to the choice bit
            ElGamal.Ciphertext selectedCiphertext = otCiphertextsForBit[i][choiceBit];

            // Decrypt with OT receiver secret key for that OT
            BigInteger decryptedBigInt = elGamal.decrypt(selectedCiphertext, secretKeys[i]);

            // Convert decrypted BigInteger to 128-bit key (16 bytes)
            byte[] keyBytes = bigIntToFixedLengthBytes(decryptedBigInt, 16);
            garbledInputKeys[i] = keyBytes;
        }
        return garbledInputKeys;
    }

    /**
     * Helper function to convert BigInteger to fixed length byte array with zero padding.
     */
    private byte[] bigIntToFixedLengthBytes(BigInteger bigInt, int length) {
        byte[] bytes = bigInt.toByteArray();
        if (bytes.length == length) {
            return bytes;
        } else if (bytes.length > length) {
            // In case there's a leading 0 byte for sign, trim it
            return Arrays.copyOfRange(bytes, bytes.length - length, bytes.length);
        } else {
            // pad with zeros on the left	<- "masking"
            byte[] padded = new byte[length];
            System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
            return padded;
        }
    }

    /**
     * Alice decrypts the garbled circuit output using one of her secret keys.
     */
    public BigInteger decryptGarbledOutput(ElGamal.Ciphertext garbledOutputCiphertext, int keyIndex) {
        if (keyIndex < 0 || keyIndex >= n) {
            throw new IllegalArgumentException("Invalid key index for decryption");
        }
        return elGamal.decrypt(garbledOutputCiphertext, secretKeys[keyIndex]);
    }

    /**
     * Getter for Alice's secret keys <- for debug
     */
    public ElGamal.SecretKey[] getSecretKeys() {
        return secretKeys;
    }
}
