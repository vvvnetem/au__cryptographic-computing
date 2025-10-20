
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Bob: garbler + OT sender.
 *
 * Notation-friendly variable names:
 *  - Alice input bits: xA, xB, xR  (wires 0..2)
 *  - Bob input bits:   yA, yB, yR  (wires 3..5)
 *  - notY_A, notY_B, notY_R are wires 6..8
 *  - OR outputs: wires 9..11
 *  - AND combine: wires 12..13 (final is 13)
 */
public class Bob {
    private final SecureRandom rnd = new SecureRandom();
    private final MessageDigest sha256;

    // All wires (14 total)
    public final WireLabel[][] wireLabels = new WireLabel[14][2]; // [wireIndex][value]
    public final List<GarbledGate> garbledCircuit = new ArrayList<>();
    public byte[] decodingZ0;
    public byte[] decodingZ1;

    // OT helper
    public final ElGamalOT ot;

    public Bob() throws Exception {
        sha256 = MessageDigest.getInstance("SHA-256");
        // choose ElGamal params
        ot = new ElGamalOT(512);
    }

    /** Generate random labels and garble the gates (NOT/OR/AND network) */
    public void garbleCircuit() throws Exception {
        // 1) generate random labels for wires 0..13
        for (int i = 0; i < 14; i++) {
            for (int v = 0; v < 2; v++) {
                byte[] lb = new byte[16];
                rnd.nextBytes(lb);
                wireLabels[i][v] = new WireLabel(lb);
            }
        }

        // We'll add gates in topological order. For gate IDs use index in garbledCircuit list.
        garbledCircuit.clear();

        // -- NOT gates: inputs 3..5 -> outputs 6..8 (notY)
        garbledCircuit.add(makeUnaryGate(3, 6, "NOT"));
        garbledCircuit.add(makeUnaryGate(4, 7, "NOT"));
        garbledCircuit.add(makeUnaryGate(5, 8, "NOT"));

        // -- OR gates: (xA OR notY_A) etc -> outputs 9..11
        garbledCircuit.add(makeBinaryGate(0, 6, 9, "OR"));
        garbledCircuit.add(makeBinaryGate(1, 7, 10, "OR"));
        garbledCircuit.add(makeBinaryGate(2, 8, 11, "OR"));

        // -- AND gates: combine 9,10 -> 12 and then 12,11 -> 13
        garbledCircuit.add(makeBinaryGate(9, 10, 12, "AND"));
        garbledCircuit.add(makeBinaryGate(12, 11, 13, "AND"));

        // decoding labels for final output wire 13
        decodingZ0 = WireLabel.toBytes(wireLabels[13][0]);
        decodingZ1 = WireLabel.toBytes(wireLabels[13][1]);
    }

    /** Helper: make unary gate (NOT). */
    private GarbledGate makeUnaryGate(int inputWire, int outputWire, String type) throws Exception {
        int gateIndex = garbledCircuit.size();
        GarbledGate g = new GarbledGate();
        // For unary gate we still create 4 entries (2 real + 2 dummy)
        // For input bit a in {0,1}, outputValue = NOT(a)
        // We'll fill entries for input a=0 and a=1, and two dummy randoms.
        // Build entries: use PRF(leftLabel, leftLabel, gateIndex) where right label is null => use zeros
        for (int a = 0; a < 2; a++) {
            int outVal = 1 - a;
            byte[] prf = PRF(wireLabels[inputWire][a].label, null, gateIndex);
            byte[] entry = new byte[32];
            // encrypted label = PRF[0..15] XOR outputLabel
            byte[] outLabel = WireLabel.toBytes(wireLabels[outputWire][outVal]);
            for (int i = 0; i < 16; i++) entry[i] = (byte) (prf[i] ^ outLabel[i]);
            // tag = PRF[16..31] (stored directly)
            System.arraycopy(prf, 16, entry, 16, 16);
            g.addEntry(entry);
        }
        // two dummy entries (random)
        for (int d = 0; d < 2; d++) {
            byte[] dummy = new byte[32];
            rnd.nextBytes(dummy);
            g.addEntry(dummy);
        }
        g.shuffle(rnd);
        return g;
    }

    /** Helper: make binary gate (AND/OR) */
    private GarbledGate makeBinaryGate(int leftWire, int rightWire, int outputWire, String type) throws Exception {
        int gateIndex = garbledCircuit.size();
        GarbledGate g = new GarbledGate();

        for (int a = 0; a < 2; a++) {
            for (int b = 0; b < 2; b++) {
                int outVal;
                if ("AND".equals(type)) outVal = (a & b);
                else if ("OR".equals(type)) outVal = (a | b);
                else throw new IllegalArgumentException("Unknown gate type " + type);
                byte[] prf = PRF(wireLabels[leftWire][a].label, wireLabels[rightWire][b].label, gateIndex);
                byte[] entry = new byte[32];
                byte[] outLabel = WireLabel.toBytes(wireLabels[outputWire][outVal]);
                for (int i = 0; i < 16; i++) entry[i] = (byte) (prf[i] ^ outLabel[i]);
                System.arraycopy(prf, 16, entry, 16, 16);
                g.addEntry(entry);
            }
        }
        g.shuffle(rnd);
        return g;
    }

    /** PRF = SHA-256(left || right || gateIndex) -> 32 bytes */
    private byte[] PRF(byte[] left, byte[] right, int gateIndex) throws Exception {
        MessageDigest sha = (MessageDigest) sha256.clone();
        sha.update(left);
        if (right != null) sha.update(right);
        sha.update((byte) gateIndex);
        return sha.digest(); // 32 bytes
    }

    // ---------- OT helper APIs used by protocol ----------
    /** Choose a random C in Z_p^* and return it (sender will use this C for OT) */
    public java.math.BigInteger chooseC() {
        java.math.BigInteger C;
        do {
            C = new java.math.BigInteger(ot.p.bitLength() - 1, rnd).mod(ot.p);
        } while (C.equals(java.math.BigInteger.ZERO));
        return C;
    }

    /** For Alice's i-th input wire, return s0,s1 (16-byte labels) */
    public byte[][] getS0S1ForAliceIndex(int i) {
        return new byte[][] { WireLabel.toBytes(wireLabels[i][0]), WireLabel.toBytes(wireLabels[i][1]) };
    }

    /** After receiving beta0,beta1 from Alice, produce SenderOutput (a0,a1,r0,r1) */
    public ElGamalOT.SenderOutput respondToOT(byte[] s0, byte[] s1, java.math.BigInteger beta0, java.math.BigInteger beta1, java.math.BigInteger C) throws Exception {
        return ot.senderRespond(s0, s1, beta0, beta1, C);
    }

    /** Encode Bob's input labels (not via OT): choose label for each of Bob's three bits */
    public WireLabel[] encodeBobInputs(int[] bobBits) {
        WireLabel[] out = new WireLabel[3];
        for (int i = 0; i < 3; i++) {
            out[i] = wireLabels[3 + i][bobBits[i]].copy();
        }
        return out;
    }

    /** Decode final output label back to bit (0/1) */
    public int decodeOutput(byte[] outputLabel) {
        if (Arrays.equals(outputLabel, decodingZ0)) return 0;
        if (Arrays.equals(outputLabel, decodingZ1)) return 1;
        return -1; // invalid
    }
}
