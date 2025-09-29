package org.example;

public class Bob {
    private final int bloodType;
    private final ElGamalAESGCM elGamal;

    public Bob(int bloodType, ElGamalAESGCM elGamal) {
        this.bloodType = bloodType;
        this.elGamal = elGamal;
    }

    public ElGamalAESGCM.Ciphertext[] encryptBloodType(ElGamalAESGCM.PublicKey[] publicKeys) {
        ElGamalAESGCM.Ciphertext[] ciphertexts = new ElGamalAESGCM.Ciphertext[8];

        for (int i = 0; i < 8; i++) {
            // Each index 'i' represents Alice's possible blood type.
            // Look up compatibility: can recipient (Alice[i]) receive from donor (this.bloodType)?
            int compatibility = Main.COMPATIBILITY_MATRIX[i][bloodType];

            byte[] message = (compatibility == 1) ? new byte[]{1} : new byte[]{0};

            try {
                // Encrypt the message with Alice's corresponding public key (real or dummy)
                ciphertexts[i] = elGamal.encrypt(message, publicKeys[i], null);
            } catch (Exception e) {
                throw new IllegalStateException("Encryption failed", e);
            }
        }

        return ciphertexts;
    }
}
