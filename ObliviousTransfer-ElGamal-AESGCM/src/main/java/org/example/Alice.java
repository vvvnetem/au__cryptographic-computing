package org.example;

public class Alice {
    private ElGamalAESGCM.KeyPair keyPair;
    private final int bloodType;
    private final ElGamalAESGCM elGamal;

    public Alice(int bloodType, ElGamalAESGCM elGamal) {
        this.bloodType = bloodType;
        this.elGamal = elGamal;
    }

    public ElGamalAESGCM.PublicKey[] createPublicKeys() {
        ElGamalAESGCM.PublicKey[] publicKeys = new ElGamalAESGCM.PublicKey[8];

        // Generate real key pair for Alice's blood type
        this.keyPair = elGamal.generateKeyPair();
        publicKeys[bloodType] = keyPair.publicKey;

        // Generate fake public keys for all other slots
        for (int i = 0; i < 8; i++) {
            if (i != bloodType) {
                publicKeys[i] = elGamal.oGen();
            }
        }

        return publicKeys;
    }

    public byte[] retrieveResult(ElGamalAESGCM.Ciphertext[] ciphertexts) {
        ElGamalAESGCM.Ciphertext ct = ciphertexts[bloodType];
        try {
            return elGamal.decrypt(ct, keyPair.secretKey, null);
        } catch (Exception e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }
}
