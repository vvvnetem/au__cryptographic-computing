# Garbled Circuit with ElGamal OT - Blood Type Compatibility

This project implements a **secure two-party computation (2PC)** for determining blood type compatibility using:

- **Garbled Circuits** for boolean function evaluation
- **ElGamal-based 1-out-of-2 Oblivious Transfer (OT)** for secure input transfer
- Unit tests for **all 8×8 recipient-donor combinations**

## 2PC

### Bob (Garbler)
- Generates random labels for all wires.
- Constructs **NOT, OR, AND gates** according to the boolean function.
- Shuffles garbled gate entries to hide plaintext logic.
- Acts as **OT sender** to transfer Alice's input labels securely.

### Alice (Evaluator)
- Uses OT to receive **only the labels corresponding to her input bits**.
- Receives Bob’s input labels directly (encoded as wire labels).
- Evaluates the garbled circuit in **topological order**.
- Obtains the final output label, which Bob can decode to **0 or 1**.

### ElGamal OT
- Ensures that Alice receives **only her chosen input labels** without revealing her choice.
- Protects Bob’s input labels from being revealed to Alice.
- Maliciously secure variants can verify the integrity of OT exchanges.


## Security Considerations

The implementation uses the following considerations:

- 512-bit safe prime ElGamal parameters
- SHA-256 as PRF / mask derivation
- XOR-based encryption for wire labels

**Malicious OT** is resistant to a corrupted receiver, provided cryptographic parameters are chosen securely.

---

## Dependencies

- Java 25+
- Maven
- JUnit 5 (for testing)

---

## Run all tests

After importing the project into IntelliJ (or any IDE) or using Maven from the command line, you can execute the automated tests with:


```
mvn test
```



