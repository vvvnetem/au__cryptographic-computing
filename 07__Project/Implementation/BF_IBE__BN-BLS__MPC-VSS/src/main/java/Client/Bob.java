package Client;

import crypto.BF_IBE;
import crypto.DPK;
import it.unisa.dia.gas.jpbc.Element;

import java.util.HashMap;
import java.util.Map;

public class Bob {

    private String id;
    private DPK dpk;
    private BF_IBE ibe;

    public Bob(String id, DPK dpk, BF_IBE ibe) {
        this.id = id;
        this.dpk = dpk;
        this.ibe = ibe;
    }

    public Map<Integer, Element> computePartialKeys(int[] nodeIndices) {
        Map<Integer, Element> partials = new HashMap<>();
        for (int idx : nodeIndices)
            partials.put(idx, dpk.computePartialKey(ibe, idx, id));
        return partials;
    }

    public Element reconstructPrivateKey(Map<Integer, Element> partials) {
        return dpk.reconstructKey(ibe, partials);
    }

    public String getId() { return id; }
}
