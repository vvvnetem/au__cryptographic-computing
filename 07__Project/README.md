# Cryptographic Computing Project: 

## Problem Description

## Running tests

---

## Design choices and parameter justifications

### Pairings over BN, BLS elliptic curves

### HMAC Key derivation function: BLAKE vs SHA256

### Multi-party Computation vs. Distributed Key Protocol

---

## Implementation specific notes

### Architecture Overview

```
       +------------------------+
       | MPC/Shamir (t-of-n)    |
       +------------------------+
                 |
          master_seed (shared)
                 |
     +-----------+-------------------+                  <=== Adaptability
     |           |                   |
     v           v                   v
  Ed25519 SK   BN MSK             BLS MSK
  (Bouncy)     (JPBC pairing)     (JPBC pairing)
                 |
             Threshold PKG
  (Partial keys from shares → reconstruct)
                 |
             Boneh–Franklin IBE
       (H1(ID) → G1, d_ID = s * Q_ID)
                 |
          Encrypt / Decrypt

```


__TODO:__ Instead of `JPBC` we need to use `bouncycastle` + `relic` via JNI.


### Project structure

```
src/main/java/
    Client/
        Alice.java
        Bob.java
    crypto/
        BF_IBE.java
        DPK.java
        ThresholdCryptography.java
src/test/java/
    Client/
        AliceBobTest.java

```

Packages:
* Client
* crypto


#### Classes overview

<!-- Shamir's secret share Part I -->
* `MPCSeedGenerator.java`
    * Ed25519 key generation
    * Shamir secret sharing of seed
    * PrivateKey Reconstruction for testing
    

<!-- Shamir's secret share Part II -->
* `ThresholdCryptography.java`
    * Shamir split/reconstruction
    * HKDF-BLAKE2b derivation
    
<!-- Boneh-Franklin based IBE Scheme -->
* `BF_IBE.java`
    * IBE operations (hash, extract, encrypt, decrypt)
    * Configurable pairing curve (BN638 or BLS24_477)
    

* `DPK.java`
    * Threshold PKG
    * Partial key computation
    * Key Reconstruction using Lagrange interpolation

* `Alice.java / Bob.java`
    * Client/server logic
    * Alice encrypts to Bob using BF IBE
    * Bob reconstructs private key from threshold PKG and decrypts <- bob-nak nem kell rekonstrualni semmilyen private kulcsot. Ezt a tesztet a DKG-en kell lefuttatni csak erdekess

__TODO:__ `Bob` reconstructs private key from threshold PKG and decrypts <- bob-nak nem kell rekonstrualni semmilyen private kulcsot. Ezt a tesztet a DKG-en kell lefuttatni unit test-el.

The design ensures:

<!-- Justifications:  efficiency + speed --->
* Ed25519 is used only for generating the master seed for MPC/Shamir.
* Supports BN638 and BLS24_477 curves for Boneh–Franklin IBE.

<!-- Justifications: adaptability, flexibility, choice to use different cryptosystems --->
* Threshold PKG with partial key computation and reconstruction.

<!-- Justifications: Flexibility, get rid of classical CA + key management --->
* Alice/Bob client-server messaging using BF IBE.


### JNI wrapper for `relic-toolkit`


