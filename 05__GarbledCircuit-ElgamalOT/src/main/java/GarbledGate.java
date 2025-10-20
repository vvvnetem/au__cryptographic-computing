
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A garbled gate holds 4 entries; each entry is 32 bytes:
 * - first 16 bytes: encrypted output label
 * - next 16 bytes: authentication tag (stored as PRF[16..31])
 *
 * The garbler will shuffle entries before sending them to the evaluator.
 */
public class GarbledGate {
    public final List<byte[]> entries = new ArrayList<>(4); // each entry length = 32

    public void addEntry(byte[] e) {
        if (e.length != 32) throw new IllegalArgumentException("entry must be 32 bytes");
        entries.add(e);
    }

    public void shuffle(java.security.SecureRandom rnd) {
        Collections.shuffle(entries, rnd);
    }
}
