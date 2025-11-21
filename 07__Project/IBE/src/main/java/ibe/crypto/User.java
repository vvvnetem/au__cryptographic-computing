package ibe.crypto;

import ibe.core.Ciphertext;
import ibe.core.PrivateKey;
import ibe.core.SystemParameters;
import ibe.threshold.PKGServer;
import ibe.threshold.ThresholdKeyExtraction;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Represents a user (Alice or Bob) in the IBE system.
 * Users can encrypt messages to others and decrypt messages sent to them.
 */
public class User {

    private final String identity;
    private final SystemParameters systemParameters;
    private PrivateKey privateKey; // Obtained from servers when needed

    public User(String identity, SystemParameters systemParameters) {
        this.identity = identity;
        this.systemParameters = systemParameters;
        this.privateKey = null;
    }

    public String getIdentity() {
        return identity;
    }

    /**
     * Request private key from PKG servers.
     * User contacts threshold number of servers and combines partial keys.
     */
    public void requestPrivateKey(List<PKGServer> servers) {
        System.out.printf("\n%s is requesting their private key...\n", identity);
        this.privateKey = ThresholdKeyExtraction.extractPrivateKey(
                identity,
                servers,
                systemParameters
        );
        System.out.printf("%s received their private key ✓\n", identity);
    }

    /**
     * Encrypt a message for another user.
     * Only needs the recipient's identity - no need for their private key!
     * Automatically pads message to required length.
     */
    public Ciphertext encryptMessage(String recipientIdentity, String message) {
        // Auto-pad the message
        String paddedMessage = padMessage(message, systemParameters.getMessageLengthBytes());

        System.out.printf("\n%s encrypting message for %s: \"%s\"\n",
                identity, recipientIdentity, message);

        byte[] messageBytes = paddedMessage.getBytes(StandardCharsets.UTF_8);
        Ciphertext ciphertext = IBEEncrypt.encrypt(
                systemParameters,
                recipientIdentity,
                messageBytes
        );

        System.out.printf("%s encrypted message ✓\n", identity);
        return ciphertext;
    }

    /**
     * Decrypt a message sent to this user.
     * Requires the user's private key.
     * Automatically unpads the decrypted message.
     */
    public String decryptMessage(Ciphertext ciphertext) {
        if (privateKey == null) {
            throw new IllegalStateException(
                    identity + " doesn't have a private key yet! Call requestPrivateKey() first."
            );
        }

        System.out.printf("\n%s decrypting received message...\n", identity);

        byte[] messageBytes = IBEDecrypt.decrypt(
                systemParameters,
                privateKey,
                ciphertext
        );

        String message = new String(messageBytes, StandardCharsets.UTF_8);
        String unpaddedMessage = unpadMessage(message);

        System.out.printf("%s decrypted message: \"%s\" ✓\n", identity, unpaddedMessage);

        return unpaddedMessage;
    }

    public boolean hasPrivateKey() {
        return privateKey != null;
    }

    /**
     * Pad message to exact length required by the system.
     */
    private String padMessage(String message, int length) {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        if (messageBytes.length > length) {
            throw new IllegalArgumentException(
                    String.format("Message too long: %d bytes, max %d bytes",
                            messageBytes.length, length));
        }

        if (messageBytes.length == length) {
            return message;
        }

        // Pad with spaces
        byte[] padded = new byte[length];
        System.arraycopy(messageBytes, 0, padded, 0, messageBytes.length);
        Arrays.fill(padded, messageBytes.length, length, (byte) ' ');

        return new String(padded, StandardCharsets.UTF_8);
    }

    /**
     * Remove padding from decrypted message.
     */
    private String unpadMessage(String paddedMessage) {
        return paddedMessage.stripTrailing();
    }

    @Override
    public String toString() {
        return String.format("User{identity='%s', hasKey=%s}", identity, hasPrivateKey());
    }
}