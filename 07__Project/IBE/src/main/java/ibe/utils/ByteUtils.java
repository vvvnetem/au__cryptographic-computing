package ibe.utils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Utility functions for byte array operations
 */
public class ByteUtils {

    /**
     * XOR two byte arrays
     * @throws IllegalArgumentException if arrays have different lengths
     */
    public static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException(
                    String.format("Array lengths must match: %d != %d", a.length, b.length)
            );
        }

        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    /**
     * Convert string to bytes using UTF-8
     */
    public static byte[] stringToBytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Convert bytes to string using UTF-8
     */
    public static String bytesToString(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * Concatenate multiple byte arrays
     */
    public static byte[] concatenate(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    /**
     * Convert byte array to hex string for debugging
     */
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Securely compare two byte arrays (constant time)
     */
    public static boolean secureEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}