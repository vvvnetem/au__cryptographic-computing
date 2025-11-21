package ibe.pairing;

import ibe.core.interfaces.PairingScheme;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

import java.io.*;
import java.math.BigInteger;

/**
 * Implementation of PairingScheme using JPBC library.
 * This wraps JPBC's pairing functionality to match our interface.
 * Compatible with JPBC 2.0.0
 */
public class JPBCPairingScheme implements PairingScheme, Serializable {
    private static final long serialVersionUID = 1L;

    private transient Pairing pairing;
    private final String pairingParametersString;

    /**
     * Create pairing scheme from JPBC pairing and parameters string
     */
    public JPBCPairingScheme(Pairing pairing, String parametersString) {
        this.pairing = pairing;
        this.pairingParametersString = parametersString;
    }

    /**
     * Wrapper for G1 elements (additive group)
     */
    public static class JPBCGroup1Element implements G1Element, Serializable {
        private static final long serialVersionUID = 1L;

        private transient Element element;
        private final byte[] cachedBytes;
        private transient Pairing pairing; // Need pairing for reconstruction

        public JPBCGroup1Element(Element element, Pairing pairing) {
            if (!element.isImmutable()) {
                this.element = element.getImmutable();
            } else {
                this.element = element;
            }
            this.pairing = pairing;
            this.cachedBytes = this.element.toBytes();
        }

        @Override
        public G1Element add(G1Element other) {
            JPBCGroup1Element otherJPBC = (JPBCGroup1Element) other;
            Element result = element.duplicate().add(otherJPBC.element).getImmutable();
            return new JPBCGroup1Element(result, pairing);
        }

        @Override
        public G1Element multiply(BigInteger scalar) {
            // In JPBC, for additive groups (G1), scalar multiplication is done with mul(BigInteger)
            Element result = element.duplicate().mul(scalar).getImmutable();
            return new JPBCGroup1Element(result, pairing);
        }

        @Override
        public G1Element duplicate() {
            return new JPBCGroup1Element(element.duplicate(), pairing);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof JPBCGroup1Element)) return false;
            JPBCGroup1Element other = (JPBCGroup1Element) obj;
            return element.isEqual(other.element);
        }

        @Override
        public boolean isIdentity() {
            return element.isZero(); // In additive notation, identity is zero
        }

        @Override
        public byte[] toBytes() {
            return cachedBytes.clone();
        }

        @Override
        public int getByteLength() {
            return cachedBytes.length;
        }

        public Element getElement() {
            return element;
        }

        void setPairing(Pairing pairing) {
            this.pairing = pairing;
        }

        @Override
        public int hashCode() {
            return element.hashCode();
        }
    }

    /**
     * Wrapper for G2/GT elements (multiplicative group)
     */
    public static class JPBCGroup2Element implements G2Element, Serializable {
        private static final long serialVersionUID = 1L;

        private transient Element element;
        private final byte[] cachedBytes;
        private transient Pairing pairing;

        public JPBCGroup2Element(Element element, Pairing pairing) {
            if (!element.isImmutable()) {
                this.element = element.getImmutable();
            } else {
                this.element = element;
            }
            this.pairing = pairing;
            this.cachedBytes = this.element.toBytes();
        }

        @Override
        public G2Element multiply(G2Element other) {
            JPBCGroup2Element otherJPBC = (JPBCGroup2Element) other;
            Element result = element.duplicate().mul(otherJPBC.element).getImmutable();
            return new JPBCGroup2Element(result, pairing);
        }

        @Override
        public G2Element pow(BigInteger exponent) {
            // For multiplicative groups (GT), use pow
            Element result = element.duplicate().pow(exponent).getImmutable();
            return new JPBCGroup2Element(result, pairing);
        }

        @Override
        public G2Element duplicate() {
            return new JPBCGroup2Element(element.duplicate(), pairing);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof JPBCGroup2Element)) return false;
            JPBCGroup2Element other = (JPBCGroup2Element) obj;
            return element.isEqual(other.element);
        }

        @Override
        public boolean isIdentity() {
            return element.isOne(); // In multiplicative notation, identity is one
        }

        @Override
        public byte[] toBytes() {
            return cachedBytes.clone();
        }

        @Override
        public int getByteLength() {
            return cachedBytes.length;
        }

        public Element getElement() {
            return element;
        }

        void setPairing(Pairing pairing) {
            this.pairing = pairing;
        }

        @Override
        public int hashCode() {
            return element.hashCode();
        }
    }

    @Override
    public BigInteger getGroupOrder() {
        return pairing.getZr().getOrder();
    }

    @Override
    public G1Element getG1Generator() {
        Element generator = pairing.getG1().newRandomElement().getImmutable();
        return new JPBCGroup1Element(generator, pairing);
    }

    @Override
    public G1Element getRandomG1Element() {
        Element random = pairing.getG1().newRandomElement().getImmutable();
        return new JPBCGroup1Element(random, pairing);
    }

    @Override
    public G1Element getG1Identity() {
        Element identity = pairing.getG1().newZeroElement().getImmutable();
        return new JPBCGroup1Element(identity, pairing);
    }

    @Override
    public G2Element getG2Identity() {
        Element identity = pairing.getGT().newOneElement().getImmutable();
        return new JPBCGroup2Element(identity, pairing);
    }

    @Override
    public G2Element pair(G1Element p, G1Element q) {
        JPBCGroup1Element pJPBC = (JPBCGroup1Element) p;
        JPBCGroup1Element qJPBC = (JPBCGroup1Element) q;

        Element result = pairing.pairing(pJPBC.getElement(), qJPBC.getElement()).getImmutable();
        return new JPBCGroup2Element(result, pairing);
    }

    @Override
    public G1Element g1FromBytes(byte[] bytes) {
        Element element = pairing.getG1().newElementFromBytes(bytes).getImmutable();
        return new JPBCGroup1Element(element, pairing);
    }

    @Override
    public G2Element g2FromBytes(byte[] bytes) {
        Element element = pairing.getGT().newElementFromBytes(bytes).getImmutable();
        return new JPBCGroup2Element(element, pairing);
    }

    @Override
    public String getName() {
        return "JPBC Pairing (Type A)";
    }

    /**
     * Get the underlying JPBC pairing (for internal use)
     */
    public Pairing getJPBCPairing() {
        return pairing;
    }

    public String getParametersString() {
        return pairingParametersString;
    }

    /**
     * Custom serialization
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
    }

    /**
     * Custom deserialization - reconstruct the pairing
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // Reconstruct pairing from parameters string
        ByteArrayInputStream bais = new ByteArrayInputStream(pairingParametersString.getBytes());
        PairingParameters params = new PropertiesParameters().load(bais);
        this.pairing = PairingFactory.getPairing(params);
    }
}