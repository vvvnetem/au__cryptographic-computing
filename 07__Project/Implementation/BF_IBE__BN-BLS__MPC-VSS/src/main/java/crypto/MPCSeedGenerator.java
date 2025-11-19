package crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public class MPCSeedGenerator {

    private byte[] masterSeed;

    public MPCSeedGenerator() {
        generateMasterSeed();
    }

    private void generateMasterSeed() {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new KeyGenerationParameters(new SecureRandom(), 256));
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
        Ed25519PrivateKeyParameters priv = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        masterSeed = priv.getEncoded();
        System.out.println("Generated Ed25519 master seed: " + bytesToHex(masterSeed));
    }

    public byte[] getMasterSeed() { return masterSeed; }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
