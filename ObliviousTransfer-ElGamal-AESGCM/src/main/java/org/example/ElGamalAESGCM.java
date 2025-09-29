package org.example;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * ElGamal hybrid encryption using AES-GCM for the symmetric layer.
 *
 * - Classic multiplicative-group ElGamal (safe prime p = 2q + 1).
 * - Ephemeral DH: shared secret s = y^k mod p.
 * - HKDF-SHA256(s) -> 32 bytes AES key.
 * - AES-GCM-256 for IND-CPA (and integrity/authentication).
 *
 * NOTE: Educational prototype. For production: prefer EC (X25519) or vetted crypto libraries,
 * ensure parameter persistence, and consider constant-time implementations.
 */
public class ElGamalAESGCM {
    private static final SecureRandom RANDOM = new SecureRandom();

    // Security parameter for classic (non-EC) ElGamal. 2048 is the practical minimum.
    private static final int BIT_LENGTH = 2048;

    private final BigInteger p; // safe prime p = 2q + 1
    private final BigInteger q; // subgroup order
    private final BigInteger g; // generator of order q

    public ElGamalAESGCM() {
        // Generate safe prime p = 2*q + 1
        BigInteger qCandidate, pCandidate;
        while (true) {
            qCandidate = BigInteger.probablePrime(BIT_LENGTH - 1, RANDOM);
            pCandidate = qCandidate.shiftLeft(1).add(BigInteger.ONE); // 2*q + 1
            if (pCandidate.isProbablePrime(100)) break;
        }
        this.q = qCandidate;
        this.p = pCandidate;
        this.g = findGenerator(p, q);
    }

    private static BigInteger findGenerator(BigInteger p, BigInteger q) {
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger exp = pMinus1.divide(q); // (p-1)/q
        while (true) {
            BigInteger h = new BigInteger(p.bitLength(), RANDOM);
            if (h.compareTo(BigInteger.TWO) < 0 || h.compareTo(pMinus1) >= 0) continue;
            BigInteger candidate = h.modPow(exp, p); // candidate has order dividing q
            if (candidate.compareTo(BigInteger.ONE) > 0 && candidate.modPow(q, p).equals(BigInteger.ONE)) {
                // candidate != 1 and has order q
                return candidate;
            }
        }
    }

    // --- Key containers ---
    public static class PublicKey {
        public final BigInteger y; // y = g^x mod p
        public PublicKey(BigInteger y) { this.y = y; }
    }

    public static class SecretKey {
        public final BigInteger x; // private exponent
        public SecretKey(BigInteger x) { this.x = x; }
    }

    public static class KeyPair {
        public final PublicKey publicKey;
        public final SecretKey secretKey;
        public KeyPair(PublicKey pub, SecretKey sec) { this.publicKey = pub; this.secretKey = sec; }
    }

    // Hybrid ciphertext: ElGamal c1 (group element) + AES-GCM ciphertext bytes + IV
    public static class Ciphertext {
        public final BigInteger c1; // g^k mod p
        public final byte[] iv;    // AES-GCM IV (12 bytes)
        public final byte[] ct;    // AES-GCM ciphertext (includes tag)

        public Ciphertext(BigInteger c1, byte[] iv, byte[] ct) {
            this.c1 = c1;
            this.iv = iv;
            this.ct = ct;
        }

        public String toBase64() {
            String sC1 = Base64.getEncoder().encodeToString(stripLeadingZero(c1.toByteArray()));
            String sIV = Base64.getEncoder().encodeToString(iv);
            String sCT = Base64.getEncoder().encodeToString(ct);
            return sC1 + ":" + sIV + ":" + sCT;
        }

        public static Ciphertext fromBase64(String b64) {
            String[] parts = b64.split(":");
            if (parts.length != 3) throw new IllegalArgumentException("Invalid ciphertext format");
            BigInteger c1 = new BigInteger(1, Base64.getDecoder().decode(parts[0]));
            byte[] iv = Base64.getDecoder().decode(parts[1]);
            byte[] ct = Base64.getDecoder().decode(parts[2]);
            return new Ciphertext(c1, iv, ct);
        }
    }

    // --- Key generation ---
    public KeyPair generateKeyPair() {
        BigInteger x;
        do {
            x = new BigInteger(q.bitLength(), RANDOM);
        } while (x.compareTo(BigInteger.ONE) <= 0 || x.compareTo(q) >= 0);

        BigInteger y = g.modPow(x, p);
        return new KeyPair(new PublicKey(y), new SecretKey(x));
    }

    /**
     * oGen: generate a random public-key-like element h = g^s mod p with fresh secret s in [1, q-1].
     * Useful when a protocol requires a random group element / ephemeral public key.
     */
    public PublicKey oGen() {
        BigInteger s;
        do {
            s = new BigInteger(q.bitLength(), RANDOM);
        } while (s.compareTo(BigInteger.ONE) <= 0 || s.compareTo(q) >= 0);

        BigInteger h = g.modPow(s, p);
        return new PublicKey(h);
    }

    // --- Hybrid encryption (ElGamal + HKDF + AES-GCM) ---
    public Ciphertext encrypt(byte[] plaintext, PublicKey publicKey, byte[] aad) throws Exception {
        // 1) Ephemeral k in [1, q-1]
        BigInteger k;
        do {
            k = new BigInteger(q.bitLength(), RANDOM);
        } while (k.compareTo(BigInteger.ONE) <= 0 || k.compareTo(q) >= 0);

        BigInteger c1 = g.modPow(k, p);

        // 2) shared secret: s = y^k mod p
        BigInteger s = publicKey.y.modPow(k, p);
        byte[] sBytes = stripLeadingZero(s.toByteArray());

        // 3) Derive symmetric key material with HKDF-SHA256
        byte[] key = hkdfExtractAndExpand(null, sBytes, "ElGamal-AES-GCM".getBytes(), 32);

        // 4) Encrypt plaintext with AES-GCM-256
        byte[] iv = new byte[12]; // 96-bit nonce for GCM
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        if (aad != null) cipher.updateAAD(aad);
        byte[] ct = cipher.doFinal(plaintext);

        return new Ciphertext(c1, iv, ct);
    }

    public byte[] decrypt(Ciphertext ciphertext, SecretKey secretKey, byte[] aad) throws Exception {
        // 1) Recover shared secret s = c1^x mod p
        BigInteger s = ciphertext.c1.modPow(secretKey.x, p);
        byte[] sBytes = stripLeadingZero(s.toByteArray());

        // 2) Derive symmetric key via HKDF
        byte[] key = hkdfExtractAndExpand(null, sBytes, "ElGamal-AES-GCM".getBytes(), 32);

        // 3) Decrypt AES-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, ciphertext.iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        if (aad != null) cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext.ct);
    }

    // --- Simple HKDF-SHA256 (extract+expand). Small example implementation ---
    private static byte[] hkdfExtractAndExpand(byte[] salt, byte[] ikm, byte[] info, int length) throws Exception {
        if (salt == null) salt = new byte[32]; // zeros
        byte[] prk = hmacSha256(salt, ikm); // extract

        int hashLen = 32;
        int n = (length + hashLen - 1) / hashLen;
        byte[] okm = new byte[length];
        byte[] t = new byte[0];

        for (int i = 1, pos = 0; i <= n; i++) {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(prk, "HmacSHA256");
            mac.init(keySpec);
            mac.update(t);
            if (info != null) mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();

            int copy = Math.min(t.length, length - pos);
            System.arraycopy(t, 0, okm, pos, copy);
            pos += copy;
        }
        return okm;
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    private static byte[] stripLeadingZero(byte[] in) {
        if (in.length > 1 && in[0] == 0) {
            return Arrays.copyOfRange(in, 1, in.length);
        }
        return in;
    }

    // --- Accessors ---
    public BigInteger getP() { return p; }
    public BigInteger getQ() { return q; }
    public BigInteger getG() { return g; }

    // --- Example main ---
    public static void main(String[] args) throws Exception {
        ElGamalAESGCM eg = new ElGamalAESGCM();
        System.out.println("p bits: " + eg.getP().bitLength());
        KeyPair kp = eg.generateKeyPair();

        String msg = "IND-CPA ElGamal with AES-GCM";
        Ciphertext ct = eg.encrypt(msg.getBytes(), kp.publicKey, null);
        System.out.println("Ciphertext (b64): " + ct.toBase64());

        byte[] pt = eg.decrypt(ct, kp.secretKey, null);
        System.out.println("Decrypted: " + new String(pt));
    }
}
