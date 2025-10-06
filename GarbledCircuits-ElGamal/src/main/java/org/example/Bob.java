package org.example;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;

public class Bob {

    private static final int LABEL_SIZE = 16; // 128 bits
    private SecureRandom random = new SecureRandom();

    // Garbled Circuit components
    public static class GarbledGate {
        // Each gate has 4 ciphertexts (garbled table)
        // Each ciphertext is a pair (K^i_{c}, tau) combined into a byte array of length 32
        // We store them as byte[][] of length 4, each 32 bytes (16 bytes K' + 16 bytes tau)
        public byte[][] ciphertexts = new byte[4][LABEL_SIZE * 2];
        public int leftWire;
        public int rightWire;
        public int outputWire;

        public GarbledGate(int left, int right, int out) {
            leftWire = left;
            rightWire = right;
            outputWire = out;
        }
    }

    public static class GarbledCircuit {
        public List<GarbledGate> gates = new ArrayList<>();
        public Map<Integer, byte[][]> wireLabels = new HashMap<>(); // wire -> {K_0, K_1}
        public int outputWire;
        public byte[] Z0;
        public byte[] Z1;
    }

    private GarbledCircuit garbledCircuit;
    private byte[][] e_x; // Alice input encoding keys {K0_i, K1_i}
    private byte[][] e_y; // Bob input encoding keys {K0_i, K1_i}

    private int n; // input size per party

    public Bob(int n) {
        this.n = n;
    }

    // --- PRF G implemented with HMAC-SHA256 truncated to 256 bits then split ---
    // G(A,B,i) outputs 2*LABEL_SIZE bytes = 32 bytes = K' || tau
    // Input: A, B - 16 bytes each, i - gate index
    private byte[] G(byte[] A, byte[] B, int i) throws Exception {
        // Key is A||B
        byte[] key = new byte[A.length + B.length];
        System.arraycopy(A, 0, key, 0, A.length);
        System.arraycopy(B, 0, key, A.length, B.length);

        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(key, "HmacSHA256"));

        // domain separate by i
        byte[] iBytes = ByteBuffer.allocate(4).putInt(i).array();
        byte[] out = hmac.doFinal(iBytes);

        // To get 32 bytes output (K' || tau), repeat or extend HMAC
        // but HMAC-SHA256 output is already 32 bytes, so perfect.

        return out; // 32 bytes: first 16 K', next 16 tau
    }

    // --- Random 128-bit key generator ---
    private byte[] randomLabel() {
        byte[] label = new byte[LABEL_SIZE];
        random.nextBytes(label);
        return label;
    }

    /** FIX: itt nem csak NAND-gat van !!
     * Garble function Gb: input f (represented by gates), output (F,e,d)
     * We'll assume f is a NAND circuit described externally as a list of gates with wire indices.
     */
    public void garbleCircuit(List<Gate> circuitGates, int totalWires, int outputWire) throws Exception {
        garbledCircuit = new GarbledCircuit();
        garbledCircuit.outputWire = outputWire;

        // 1. Generate wire labels for all wires
        for (int w = 1; w <= totalWires; w++) {
            byte[] K0 = randomLabel();
            byte[] K1 = randomLabel();
            garbledCircuit.wireLabels.put(w, new byte[][]{K0, K1});
        }

        // Set decoding info d = (Z0,Z1) for output wire
        garbledCircuit.Z0 = garbledCircuit.wireLabels.get(outputWire)[0];
        garbledCircuit.Z1 = garbledCircuit.wireLabels.get(outputWire)[1];

        // 2. Garble all gates (except input wires)
        for (Gate g : circuitGates) {
            GarbledGate gg = new GarbledGate(g.leftWire, g.rightWire, g.outputWire);

            // Build garbled table of 4 ciphertexts for NAND gate
            // For all (a,b) in {0,1}x{0,1}:
            // C'_{a,b} = G(K^{L}_a, K^{R}_b, i) XOR (K^{out}_{neg ab} || 0^k)
            // with i = outputWire index (gate ID)
            // Then permute ciphertexts randomly

            byte[][] cprime = new byte[4][LABEL_SIZE * 2];
            int idx = 0;
            for (int a = 0; a <= 1; a++) {
                for (int b = 0; b <= 1; b++) {
                    byte[] KL = garbledCircuit.wireLabels.get(g.leftWire)[a];
                    byte[] KR = garbledCircuit.wireLabels.get(g.rightWire)[b];
                    byte[] Gout = G(KL, KR, g.outputWire);

                    // NAND(a,b) = !(a & b)
                    int outBit = 1 - (a & b);
                    byte[] Kout = garbledCircuit.wireLabels.get(g.outputWire)[outBit];

                    // XOR Gout with (Kout || 0^k)
                    byte[] zero = new byte[LABEL_SIZE];
                    byte[] xorInput = new byte[LABEL_SIZE * 2];
                    System.arraycopy(Kout, 0, xorInput, 0, LABEL_SIZE);
                    System.arraycopy(zero, 0, xorInput, LABEL_SIZE, LABEL_SIZE);

                    byte[] cipher = xorBytes(Gout, xorInput);
                    cprime[idx] = cipher;
                    idx++;
                }
            }

            // Permute ciphertexts randomly
            List<Integer> perm = Arrays.asList(0, 1, 2, 3);
            Collections.shuffle(perm);
            for (int j = 0; j < 4; j++) {
                gg.ciphertexts[j] = cprime[perm.get(j)];
            }

            garbledCircuit.gates.add(gg);
        }

        // Encoding info e = ({K0_i, K1_i}_{i in input wires})
        // Alice input wires: 1..n, Bob input wires: n+1..2n (assuming)
        // So e_x = wireLabels[1..n], e_y = wireLabels[n+1..2n]
        e_x = new byte[n][];
        e_y = new byte[n][];
        for (int i = 1; i <= n; i++) {
            e_x[i - 1] = concat(garbledCircuit.wireLabels.get(i)[0], garbledCircuit.wireLabels.get(i)[1]);
        }
        for (int i = n + 1; i <= 2 * n; i++) {
            e_y[i - n - 1] = concat(garbledCircuit.wireLabels.get(i)[0], garbledCircuit.wireLabels.get(i)[1]);
        }
    }

    // --- Encode Bob's input y -> Y ---
    // y is bit vector of length n
    // Y = {K^{y_i}_i} for i in Bob input wires
    public byte[][] encodeBobInput(boolean[] y) {
        if (y.length != n) throw new IllegalArgumentException("Input length mismatch");

        byte[][] Y = new byte[n][LABEL_SIZE];
        for (int i = 0; i < n; i++) {
            byte[][] keys = garbledCircuit.wireLabels.get(n + 1 + i);
            Y[i] = keys[y[i] ? 1 : 0];
        }
        return Y;
    }

    // --- Provide encoding info for Alice's input e_x for OT ---
    // Return n pairs of keys (K0, K1) for Alice input wires 1..n
    public byte[][] getEncodingInfoForAlice() {
        // Flattened as 2 * LABEL_SIZE per entry
        return e_x;
    }

    // --- Provide garbled circuit F to Alice ---
    // Serialize garbled circuit (F): list of garbled gates with their ciphertexts
    // For simplicity, return the list of GarbledGate objects
    public List<GarbledGate> getGarbledCircuit() {
        return garbledCircuit.gates;
    }

    // --- Decode output ---
    // Given garbled output Z (label), return plaintext bit 0 or 1
    public int decodeOutput(byte[] Z) {
        if (Arrays.equals(Z, garbledCircuit.Z0)) return 0;
        if (Arrays.equals(Z, garbledCircuit.Z1)) return 1;
        throw new RuntimeException("Invalid garbled output: abort");
    }

    // --- Utility: XOR two byte arrays ---
    private byte[] xorBytes(byte[] a, byte[] b) {
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            r[i] = (byte) (a[i] ^ b[i]);
        }
        return r;
    }

    // --- Utility: concat two byte arrays ---
    private byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    // --- Helper class for gate description ---
    public static class Gate {
        public int leftWire;
        public int rightWire;
        public int outputWire;

        public Gate(int left, int right, int out) {
            this.leftWire = left;
            this.rightWire = right;
            this.outputWire = out;
        }
    }

}
