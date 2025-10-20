import java.util.Arrays;

/**
 * Simple 16-byte (128-bit) wire label container.
 */
public class WireLabel {
    public final byte[] label; // 16 bytes

    public WireLabel() {
        this.label = new byte[16];
    }

    public WireLabel(byte[] b) {
        if (b.length != 16) throw new IllegalArgumentException("WireLabel must be 16 bytes");
        this.label = Arrays.copyOf(b, 16);
    }

    public WireLabel copy() {
        return new WireLabel(this.label);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof WireLabel)) return false;
        return Arrays.equals(this.label, ((WireLabel) obj).label);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(label);
    }

    public static byte[] toBytes(WireLabel w) { return Arrays.copyOf(w.label, 16); }
    public static WireLabel fromBytes(byte[] b) { return new WireLabel(b); }
}
