package Client;

import crypto.BF_IBE;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class Alice {

    private String id;
    private BF_IBE ibe;

    public Alice(String id, BF_IBE ibe) {
        this.id = id;
        this.ibe = ibe;
    }

    public Map<String, Element> encrypt(String recipientId, Element message) {
        return ibe.encrypt(recipientId, message);
    }

    public Element decrypt(Element privateKey, Map<String, Element> ciphertext) {
        return ibe.decrypt(privateKey, ciphertext);
    }

    public String getId() { return id; }
}
