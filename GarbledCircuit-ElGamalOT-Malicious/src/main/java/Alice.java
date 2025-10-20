

import java.util.Arrays;

/**
 * Alice: OT receiver and garbled-circuit evaluator.
 *
 * Notations are choosed accordingly to `f` boolean circuit formula:
 *  - Alice input labels correspond to xA,xB,xR (wires are indexed as 0..2)
 *  - Bob inputs are yA,yB,yR (wires are indexed as 3..5) provided as labels by Bob (encoded)
 */
public class Alice {

    public final int[] inputBits;     // 3-bit blood type for Alice
    public final byte[][] recoveredLabels = new byte[3][16]; // chosen via OT
    public WireLabel[] bobInputLabels; // assigned by Bob (encoded)
    private MaliciousElGamalOT.ReceiverState[] otStates = new MaliciousElGamalOT.ReceiverState[3];

    public Alice(int[] inputBits) {
        if (inputBits.length != 3) throw new IllegalArgumentException("need 3 bits");
        this.inputBits = Arrays.copyOf(inputBits, 3);
    }

    /**
     * For the i-th input bit:
     * - Given C from Bob, produce (beta0,beta1) -> ReceiverState
     */
    public MaliciousElGamalOT.ReceiverState prepareOTReceiver(MaliciousElGamalOT ot, int i, java.math.BigInteger C) {
        MaliciousElGamalOT.ReceiverState st = ot.receiverGenerateBetas(inputBits[i], C);
        otStates[i] = st;
        return st;
    }
    /** After Bob responds with SenderOutput, recover chosen label */
    public byte[] recoverFromOT(MaliciousElGamalOT ot, int i, MaliciousElGamalOT.SenderOutput so) throws Exception {
        MaliciousElGamalOT.ReceiverState st = otStates[i];
        byte[] recovered = ot.receiverRecover(st, so.a0, so.a1, so.r0, so.r1);
        System.arraycopy(recovered, 0, recoveredLabels[i], 0, 16);
        return recovered;
    }

    public void setBobEncodedInputs(WireLabel[] bobLabels) {
        this.bobInputLabels = bobLabels;
    }

    /** Evaluate garbled circuit produced by Bob.
     *  garbledCircuit: list of gates in topological order
     *  Bob used PRF with gate index = position in list for garbling
     */
    public byte[] evaluateGarbledCircuit(java.util.List<GarbledGate> garbledCircuit) throws Exception {
        // Build map of wire label bytes for wires 0..13 (we use null for unknown)
        byte[][] wireValues = new byte[14][];
        // Alice inputs 0..2 come from recoveredLabels
        for (int i = 0; i < 3; i++) wireValues[i] = Arrays.copyOf(recoveredLabels[i], 16);
        // Bob inputs 3..5 come from bobInputLabels
        for (int i = 0; i < 3; i++) wireValues[3 + i] = WireLabel.toBytes(bobInputLabels[i]);

        // Evaluate gates in sequence. For gate j, compute PRF(labelL,labelR,j) and try entries.
        for (int gateIndex = 0; gateIndex < garbledCircuit.size(); gateIndex++) {
            GarbledGate g = garbledCircuit.get(gateIndex);
            // We need the left & right wire indices used by Bob when he constructed PRF.
            // In this simplified implementation the PRF left/right were the actual labels used
            // (the garbler used the concrete labels, but we don't store indices here).
            // Therefore we need to know which wires are the inputs for gateIndex.
            // To keep it simple and deterministic we will encode the gate wiring by order:
            // Our Bob built gates in a fixed order and PRF used left/right labels of those wires.
            // We must reconstruct left & right labels in the same order.
            // We adopt the same order as Bob.garbleCircuit: (3->6),(4->7),(5->8),(0,6->9),(1,7->10),(2,8->11),(9,10->12),(12,11->13)
            int leftWire = -1, rightWire = -1, outputWire = -1;
            switch (gateIndex) {
                case 0: leftWire = 3; rightWire = -1; outputWire = 6; break; // NOT yA
                case 1: leftWire = 4; rightWire = -1; outputWire = 7; break; // NOT yB
                case 2: leftWire = 5; rightWire = -1; outputWire = 8; break; // NOT yR
                case 3: leftWire = 0; rightWire = 6; outputWire = 9; break;  // OR xA | ~yA
                case 4: leftWire = 1; rightWire = 7; outputWire = 10; break; // OR xB | ~yB
                case 5: leftWire = 2; rightWire = 8; outputWire = 11; break; // OR xR | ~yR
                case 6: leftWire = 9; rightWire = 10; outputWire = 12; break;// AND
                case 7: leftWire = 12; rightWire = 11; outputWire = 13; break;// AND final
                default: throw new IllegalStateException("unexpected gate index " + gateIndex);
            }

            byte[] leftLabel = wireValues[leftWire];
            byte[] rightLabel = (rightWire == -1) ? null : wireValues[rightWire];

            // Evaluate gate: try all entries; only one entry will have tag==PRF[16..31]
            byte[] outLabel = null;
            int validCount = 0;
            for (byte[] entry : g.entries) {
                // compute PRF(leftLabel, rightLabel, gateIndex) -> 32 bytes
                java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
                sha.update(leftLabel);
                if (rightLabel != null) sha.update(rightLabel);
                sha.update((byte) gateIndex);
                byte[] prf = sha.digest(); // 32 bytes

                // decrypt candidate output
                byte[] cand = new byte[16];
                for (int i = 0; i < 16; i++) cand[i] = (byte) (entry[i] ^ prf[i]);
                // check tag: entry[16..31] XOR prf[16..31] must be zero
                boolean tagOk = true;
                for (int i = 0; i < 16; i++) if ((byte)(entry[16 + i] ^ prf[16 + i]) != 0) { tagOk = false; break; }

                if (tagOk) {
                    outLabel = cand;
                    validCount++;
                }
            }
            if (validCount != 1 || outLabel == null) throw new RuntimeException("τ-check failed at gate " + gateIndex);
            wireValues[outputWire] = outLabel;
        }

        // final output is wire 13 (this is the output where we get Z0, Z1 on the picture)
        return wireValues[13];
    }
}
