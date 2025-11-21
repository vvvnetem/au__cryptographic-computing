package ibe.pairing;

import ibe.core.interfaces.CurveParameters;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

import java.io.ByteArrayInputStream;

/**
 * Factory for creating pairing schemes with different curve types.
 * Uses JPBC's built-in curve generators.
 * Compatible with JPBC 2.0.0
 */
public class JPBCPairingFactory {

    /**
     * Type A curves - Symmetric pairing on supersingular curves
     * Good for testing and standard security levels
     */
    public static class TypeACurve implements CurveParameters {
        private final int rBits;
        private final int qBits;

        /**
         * @param rBits Size of the group order (160 bits = ~1024 bit security)
         * @param qBits Size of the base field (512 bits recommended)
         */
        public TypeACurve(int rBits, int qBits) {
            this.rBits = rBits;
            this.qBits = qBits;
        }

        @Override
        public int getSecurityLevel() {
            return rBits;
        }

        @Override
        public String getCurveType() {
            return "Type A (Supersingular)";
        }

        @Override
        public String getParametersString() {
            TypeACurveGenerator generator = new TypeACurveGenerator(rBits, qBits);
            PairingParameters params = generator.generate();
            return params.toString();
        }

        @Override
        public String getDescription() {
            return String.format("Type A curve with %d-bit r and %d-bit q", rBits, qBits);
        }

        public int getRBits() { return rBits; }
        public int getQBits() { return qBits; }
    }

    /**
     * Predefined secure curve configurations
     */
    public static class SecureCurves {

        /**
         * Testing level - Fast but not secure for production
         * ~512-bit security equivalent
         */
        public static CurveParameters TEST_CURVE = new TypeACurve(160, 512);

        /**
         * Standard level - Good for most applications
         * ~1024-bit security equivalent
         */
        public static CurveParameters STANDARD_CURVE = new TypeACurve(256, 1024);
    }

    /**
     * Create a pairing scheme from curve parameters
     */
    public static JPBCPairingScheme createPairing(CurveParameters curveParams) {
        System.out.println("Generating pairing parameters...");
        System.out.println("  Curve: " + curveParams.getDescription());

        String paramsString = curveParams.getParametersString();

        System.out.println("  Parameters generated successfully");

        // Parse parameters from string
        ByteArrayInputStream bais = new ByteArrayInputStream(paramsString.getBytes());
        PairingParameters params = new PropertiesParameters().load(bais);

        // Create pairing from parameters
        Pairing pairing = PairingFactory.getPairing(params);
        System.out.println("  Pairing initialized");

        return new JPBCPairingScheme(pairing, paramsString);
    }

    /**
     * Create a pairing scheme with default secure parameters
     */
    public static JPBCPairingScheme createDefaultPairing() {
        return createPairing(SecureCurves.TEST_CURVE);
    }

    /**
     * Create a pairing scheme from parameters string
     */
    public static JPBCPairingScheme createFromString(String paramsString) {
        ByteArrayInputStream bais = new ByteArrayInputStream(paramsString.getBytes());
        PairingParameters params = new PropertiesParameters().load(bais);
        Pairing pairing = PairingFactory.getPairing(params);
        return new JPBCPairingScheme(pairing, paramsString);
    }
}