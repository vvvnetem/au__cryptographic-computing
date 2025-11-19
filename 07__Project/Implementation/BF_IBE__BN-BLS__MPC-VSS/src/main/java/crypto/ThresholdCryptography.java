package crypto;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class ThresholdCryptography {

    private static final SecureRandom random = new SecureRandom();

    // Shamir split
    public static List<BigInteger> shamirSplit(BigInteger secret, int n, int t, BigInteger prime) {
        BigInteger[] coeffs = new BigInteger[t];
        coeffs[0] = secret;
        for (int i = 1; i < t; i++)
            coeffs[i] = new BigInteger(prime.bitLength(), random).mod(prime);

        List<BigInteger> shares = new ArrayList<>();
        for (int x = 1; x <= n; x++) {
            BigInteger y = BigInteger.ZERO;
            BigInteger xi = BigInteger.valueOf(x);
            for (int i = 0; i < t; i++)
                y = y.add(coeffs[i].multiply(xi.pow(i))).mod(prime);
            shares.add(y);
        }
        return shares;
    }

    // Lagrange interpolation
    public static BigInteger reconstructSecret(List<Integer> indices, List<BigInteger> shareValues, BigInteger prime) {
        BigInteger secret = BigInteger.ZERO;
        int t = shareValues.size();
        for (int i = 0; i < t; i++) {
            BigInteger xi = BigInteger.valueOf(indices.get(i));
            BigInteger li = BigInteger.ONE;
            for (int j = 0; j < t; j++) {
                if (i != j) {
                    BigInteger xj = BigInteger.valueOf(indices.get(j));
                    li = li.multiply(xj.multiply(xj.subtract(xi).modInverse(prime))).mod(prime);
                }
            }
            secret = secret.add(shareValues.get(i).multiply(li)).mod(prime);
        }
        return secret;
    }

    // HKDF-BLAKE2b derivation
    public static BigInteger hkdf(byte[] seed, String info, BigInteger mod) {
        Blake2bDigest digest = new Blake2bDigest(256);
        digest.update(seed, 0, seed.length);
        byte[] infoBytes = info.getBytes();
        digest.update(infoBytes, 0, infoBytes.length);
        byte[] out = new byte[32];
        digest.doFinal(out, 0);
        return new BigInteger(1, out).mod(mod);
    }
}
