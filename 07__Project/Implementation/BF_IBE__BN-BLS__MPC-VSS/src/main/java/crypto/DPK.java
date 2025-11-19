package crypto;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.util.Map;

public class DPK {

    private int n, t;
    private BigInteger prime;
    private java.util.List<BigInteger> shares;

    public DPK(int n, int t, BigInteger prime, BigInteger masterSeed) {
        this.n = n;
        this.t = t;
        this.prime = prime;
        this.shares = ThresholdCryptography.shamirSplit(masterSeed, n, t, prime);
    }

    public java.util.List<BigInteger> getShares() { return shares; }

    public Element computePartialKey(BF_IBE ibe, int nodeIndex, String id) {
        BigInteger share = shares.get(nodeIndex - 1);
        return ibe.extract(share, id);
    }

    public Element reconstructKey(BF_IBE ibe, Map<Integer, Element> partials) {
        return ibe.combinePartialKeys(partials, prime);
    }
}
