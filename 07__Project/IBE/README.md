# Identity-Based Encryption (IBE) Implementation

A complete implementation of Identity-Based Encryption (IBE) using the BLS12-381 pairing-friendly elliptic curve from the Apache Milagro Cryptographic Library.

## Table of Contents
- [Overview](#overview)
- [Theoretical Background](#theoretical-background)
- [System Architecture](#system-architecture)
- [Usage](#usage)
- [Classes and Methods](#classes-and-methods)
- [Security Features](#security-features)
- [Testing](#testing)
- [Implementation Details](#implementation-details)
- [Future Enhancements](#future-enhancements)
- [References](#references)

---

## Overview

This project implements a full Identity-Based Encryption (IBE) system based on the Boneh-Franklin scheme. IBE is a revolutionary cryptographic approach where any arbitrary string (like an email address) can serve as a public key, eliminating the need for traditional Public Key Infrastructure (PKI) and certificate management.

### Key Features
- **Pairing-based cryptography** using BLS12-381 curve
- **Four core algorithms**: Setup, Extract, Encrypt, and Decrypt
- **Tamper detection** through cryptographic verification
- **Cross-identity security** - only the intended recipient can decrypt
- **Randomized encryption** - same message produces different ciphertexts
- **Comprehensive testing** with multiple security scenarios

### Technology Stack
- **Language**: Java 24
- **Cryptographic Library**: Apache Milagro AMCL (v0.4.0)
- **Curve**: BLS12-381 pairing-friendly curve
- **Build Tool**: Maven

---

## Theoretical Background

### What is Identity-Based Encryption?

In traditional public-key cryptography (like RSA), users must:
1. Generate a key pair
2. Distribute their public key
3. Manage certificates through a PKI

Identity-Based Encryption simplifies this by allowing any string (email, ID number, etc.) to function as a public key. A trusted Private Key Generator (PKG) derives private keys from identities using a master secret.

### Boneh-Franklin IBE Scheme

This implementation follows the Boneh-Franklin BasicIdent scheme, which uses bilinear pairings on elliptic curves.

#### Mathematical Foundation

**Groups**:
- G₁, G₂: Elliptic curve groups of prime order q
- GT: Target group for the pairing
- e: G₂ × G₁ → GT (bilinear pairing function)

**Bilinear Pairing Properties**:
1. Bilinearity: e(aP, bQ) = e(P, Q)^(ab)
2. Non-degeneracy: e(P, Q) ≠ 1 for generators P, Q
3. Computability: e(P, Q) can be efficiently computed

**Four Core Algorithms**:

1. **Setup(λ) → (params, master-key)**
   - Input: Security parameter λ
   - Choose groups G₁, G₂, GT of prime order q with pairing e
   - Pick random generators P ∈ G₁, Q ∈ G₂
   - Choose random master secret s ∈ Zq*
   - Compute P_pub = s·P and Q_pub = s·Q
   - Output: params = (q, P, Q, P_pub, Q_pub), master-key = s

2. **Extract(ID, master-key, params) → private-key**
   - Input: Identity ID, master secret s
   - Compute Q_ID = H₁(ID) ∈ G₁*
   - Compute d_ID = s·Q_ID
   - Output: private-key = d_ID

3. **Encrypt(M, ID, params) → Ciphertext**
   - Input: Message M, recipient identity ID
   - Compute Q_ID = H₁(ID)
   - Choose random σ ∈ {0,1}ⁿ
   - Compute r = H₃(σ, M) ∈ Zq*
   - Compute U = r·P
   - Compute g_ID = e(Q_pub, Q_ID)^H(U)
   - Compute V = σ ⊕ H₂(g_ID^r)
   - Compute W = M ⊕ H₄(σ)
   - Output: C = (U, V, W)

4. **Decrypt(C, private-key, params) → M**
   - Input: Ciphertext C = (U, V, W), private key d_ID
   - Check U ∈ G₁*
   - Compute pairing = e(Q, d_ID)^H(U)
   - Recover σ = V ⊕ H₂(pairing)
   - Recover M = W ⊕ H₄(σ)
   - Verify: U = H₃(σ, M)·P
   - Output: M if verification succeeds, ⊥ otherwise

#### Hash Functions

- **H₁: {0,1}* → G₁*** - Maps identities to curve points (hash-to-curve)
- **H₂: GT → {0,1}ⁿ** - Extracts symmetric key from pairing result
- **H₃: {0,1}* × {0,1}* → Zq*** - Generates random exponent from σ and M
- **H₄: {0,1}* → {0,1}ⁿ** - Key derivation for message encryption

---

## System Architecture

### Component Overview

```
ibe/
├── fourCoreAlg/
│   ├── Setup.java       # System initialization and parameter generation
│   ├── Extract.java     # Private key generation from identities
│   ├── Encrypt.java     # Message encryption algorithm
│   └── Decrypt.java     # Message decryption and verification
├── Ciphertext.java      # Ciphertext data structure
└── Main.java            # Integration tests and demonstrations
```

#### SystemParams
Contains public parameters shared by all users:
- `P`: Generator point in G₁
- `Q`: Generator point in G₂
- `P_pub`: Master public key (s·P) in G₁
- `Q_pub`: Master public key (s·Q) in G₂
- `q`: Group order (prime)
- `messageLength`: Default message length (32 bytes)

#### MasterKey
Private key held only by the PKG:
- `s`: Master secret (random element in Zq*)

#### PrivateKey
User's private decryption key:
- `identity`: User's identity string
- `d_ID`: Private key point (s·Q_ID) in G₁
- `Q_ID`: Public identity point H₁(ID) in G₁

#### Ciphertext
Encrypted message structure:
- `U`: Random point (r·P) in G₁
- `V`: Encrypted randomness (σ ⊕ H₂(pairing))
- `W`: Encrypted message (M ⊕ H₄(σ))
- `recipientIdentity`: Recipient's identity string

---



## Usage

### Basic Example

```java
import ibe.*;
import ibe.fourCoreAlg.*;
import static ibe.fourCoreAlg.Setup.*;
import static ibe.fourCoreAlg.Extract.*;
import static ibe.fourCoreAlg.Encrypt.*;
import static ibe.fourCoreAlg.Decrypt.*;

public class IBEExample {
    public static void main(String[] args) {
        // 1. System Setup (performed by PKG)
        Object[] result = setup(128);
        SystemParams params = (SystemParams) result[0];
        MasterKey masterKey = (MasterKey) result[1];
        
        // 2. Key Extraction (performed by PKG for each user)
        String bobEmail = "bob@company.com";
        PrivateKey bobKey = extract(bobEmail, masterKey, params);
        
        // 3. Encryption (anyone can encrypt for Bob)
        String message = "Hello Bob! This is a secret message.";
        Ciphertext ciphertext = encrypt(message, bobEmail, params);
        
        // 4. Decryption (only Bob can decrypt)
        String decrypted = decryptToString(ciphertext, bobKey, params);
        
        System.out.println("Original:  " + message);
        System.out.println("Decrypted: " + decrypted);
        System.out.println("Match: " + message.equals(decrypted));
    }
}
```


## Classes and Methods

### Setup Class

#### `setup(int securityParameter) → Object[]`
Initializes the IBE system.

**Parameters**:
- `securityParameter`: Security parameter (e.g., 128 for 128-bit security), but since we're using Milagro with BLS12-381, the security choices are already hardcoded


**Returns**: `Object[]` containing:
- `[0]`: `SystemParams` - Public parameters
- `[1]`: `MasterKey` - Master secret key

#### Hash Functions

##### `hashToG1(String identity) → ECP`
Maps an identity string to a point on the elliptic curve.

**Parameters**:
- `identity`: User identity string (e.g., email address)

**Returns**: Point in G₁ (ECP)

##### `hashFromGT(FP12 element, int length) → byte[]`
Extracts bytes from a pairing result.

**Parameters**:
- `element`: Element in GT (FP12)
- `length`: Desired output length in bytes

**Returns**: Byte array of specified length

##### `hashToZq(byte[] sigma, byte[] message, BIG q) → BIG`
Generates a random exponent in Zq from sigma and message.

**Parameters**:
- `sigma`: Random value
- `message`: Message bytes
- `q`: Group order

**Returns**: Element in Zq*

##### `hashToBytes(byte[] input, int length) → byte[]`
General hash function for byte array output.

**Parameters**:
- `input`: Input bytes
- `length`: Desired output length

**Returns**: Hash output as byte array

### Extract Class

#### `extract(String identity, MasterKey masterKey, SystemParams params) → PrivateKey`
Generates a private key for a given identity.

**Parameters**:
- `identity`: User's identity string
- `masterKey`: Master secret key (from PKG)
- `params`: System parameters

**Returns**: `PrivateKey` object containing d_ID

### Encrypt Class

#### `encrypt(byte[] message, String identity, SystemParams params) → Ciphertext`
Encrypts a message for a specific identity.

**Parameters**:
- `message`: Message as byte array
- `identity`: Recipient's identity string
- `params`: System parameters

**Returns**: `Ciphertext` object

#### `encrypt(String message, String identity, SystemParams params) → Ciphertext`
String convenience method.

**Parameters**:
- `message`: Message as String
- `identity`: Recipient's identity
- `params`: System parameters

**Returns**: `Ciphertext` object

### Decrypt Class

#### `decrypt(Ciphertext ciphertext, PrivateKey privateKey, SystemParams params) → byte[]`
Decrypts a ciphertext using the recipient's private key.

**Parameters**:
- `ciphertext`: Encrypted message
- `privateKey`: Recipient's private key
- `params`: System parameters

**Returns**: Decrypted message as byte array, or `null` if verification fails

#### `decryptToString(Ciphertext ciphertext, PrivateKey privateKey, SystemParams params) → String`
String convenience method.

**Returns**: Decrypted message as String, or `null` if verification fails

### Ciphertext Class

#### `toBytes() → byte[]`
Serializes the ciphertext for transmission.

**Returns**: Byte array representation

#### `fromBytes(byte[] bytes) → Ciphertext`
Deserializes a ciphertext from bytes.

**Parameters**:
- `bytes`: Serialized ciphertext

**Returns**: `Ciphertext` object

---

## Security Features

### 1. **Chosen Ciphertext Security (IND-ID-CCA)**

The implementation includes verification to ensure chosen ciphertext security:

```java
// Verification step in decryption
BIG r = hashToZq(sigma, M, params.q);
ECP expected_U = PAIR.G1mul(params.P, r);

if (!ciphertext.U.equals(expected_U)) {
    System.out.println("Error: Verification failed");
    return null;
}
```

This prevents attacks where an adversary modifies the ciphertext.

### 2. **Tamper Detection**

The scheme detects any modification to ciphertext components:
- **Modified U**: Changes the pairing result, leading to wrong σ and failed verification
- **Modified V**: Produces wrong σ, leading to wrong M and failed verification
- **Modified W**: Produces wrong M, causing U verification to fail

### 3. **Cross-Identity Security**

Only the intended recipient can decrypt:
- Each identity gets a unique private key d_ID = s·H₁(ID)
- Decryption requires the correct d_ID matching the encrypted identity
- Wrong keys produce incorrect pairing results

### 4. **Randomization**

Each encryption is randomized:
- Random σ is chosen for each encryption
- Same message encrypted twice produces different ciphertexts
- Prevents pattern analysis and replay attacks

### 5. **Key Validation**

The system validates all cryptographic elements:
- Checks for points at infinity
- Verifies proper group membership
- Ensures non-zero scalars

---

## Testing

The project includes comprehensive test suites for each component.

### Running Tests

```bash
# Individual component tests
mvn exec:java -Dexec.mainClass="ibe.fourCoreAlg.Setup"
mvn exec:java -Dexec.mainClass="ibe.fourCoreAlg.Extract"
mvn exec:java -Dexec.mainClass="ibe.fourCoreAlg.Encrypt"
mvn exec:java -Dexec.mainClass="ibe.fourCoreAlg.Decrypt"

# Integration tests
mvn exec:java -Dexec.mainClass="ibe.Main"
```

### Test Coverage

#### Setup Tests
- ✓ Parameter generation
- ✓ Group order validation
- ✓ Generator point verification
- ✓ Hash function consistency
- ✓ Pairing computation

#### Extract Tests
- ✓ Private key generation
- ✓ Multiple identities
- ✓ Key uniqueness
- ✓ Deterministic extraction
- ✓ Serialization/deserialization

#### Encrypt Tests
- ✓ Basic encryption
- ✓ Randomization (same message → different ciphertexts)
- ✓ Different Recipients
- ✓ Pairing Computation
- ✓ Edge cases 


#### Decrypt Tests
- ✓ Basic decryption
- ✓ Wrong key rejection
- ✓ Tamper detection (modified U, V, W)
- ✓ Invalid ciphertext rejection
- ✓ Edge cases 

#### Integration Tests
- ✓ Complete encrypt/decrypt cycle
- ✓ Wrong Key Rejection
- ✓ Cross-identity security
- ✓ Multiple Multiple Encryption Same Message


---

## Implementation Details

### Elliptic Curve: BLS12-381

BLS12-381 is a pairing-friendly elliptic curve offering:
- **Security**: ~128-bit security level
- **Efficiency**: Fast pairing computation
- **Standardization**: Used in Ethereum 2.0, Zcash, and other projects

**Parameters**:
- Field size: 381 bits
- Embedding degree: k = 12
- Group order: Prime q (~255 bits)
- Curve equation: y² = x³ + 4

### Pairing Function

The implementation uses the optimal Ate pairing:
```java
FP12 pairing = PAIR.fexp(PAIR.ate(Q, P));
```

Where:
- `PAIR.ate(Q, P)`: Computes raw pairing e(Q, P)
- `PAIR.fexp()`: Final exponentiation for proper GT element

### Hash-to-Curve (H₁)

Identity strings are mapped to curve points using the try-and-increment method:

```java
1. counter = 0
2. While counter < maxAttempts:
   a. h = SHA256(identity || counter)
   b. x = h mod p (field prime)
   c. Try to construct point P with x-coordinate
   d. If P is valid (not infinity), return P
   e. counter++
3. Fallback: return h·G (deterministic but less ideal)
```

This ensures deterministic and collision-resistant identity mapping.

### Key Derivation (H₂, H₄)

Both use SHA-256/SHA-512 for key derivation:
- **H₂**: Extracts symmetric key from pairing result
- **H₄**: Derives message mask from σ

For outputs longer than hash size, multiple rounds are used with counter increments.

### Random Exponent Generation (H₃)

Generates exponent r ∈ Zq* from σ and M:
```java
r = SHA256(σ || M) mod q
if r = 0: r = 1
```

This binds the ciphertext to both the randomness and message, enabling verification.

---

## Future Enhancements

Potential improvements for this implementation:

1. **Hierarchical IBE (HIBE)**: Support for identity delegation
2. **Revocation**: Implement key revocation mechanisms
3. **Time-based encryption**: Encrypt for specific time periods
4. **Threshold PKG**: Distribute PKG trust among multiple parties
5. **Performance**: Optimize pairing computations with precomputation
6. **Forward secrecy**: Add ephemeral key agreement
7. **Attribute-based**: Extend to attribute-based encryption (ABE)
8. **Key rotation**: Automated master key rotation

---

## References

### Academic Papers

1. **Boneh, D., & Franklin, M. (2001)**
   "Identity-Based Encryption from the Weil Pairing"
   *CRYPTO 2001*
   - Original IBE scheme using bilinear pairings

2. **Boneh, D., & Boyen, X. (2004)**
   "Efficient Selective-ID Secure Identity-Based Encryption Without Random Oracles"
   *EUROCRYPT 2004*

3. **Barreto, P. S. L. M., & Naehrig, M. (2005)**
   "Pairing-Friendly Elliptic Curves of Prime Order"
   *SAC 2005*
   - Foundation for BLS curves

### Technical Resources

- **Apache Milagro AMCL**: https://github.com/apache/incubator-milagro-crypto-c
- **BLS12-381 Specification**: https://hackmd.io/@benjaminion/bls12-381
- **IETF Pairing-Friendly Curves**: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/

