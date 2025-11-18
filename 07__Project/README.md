# Boneh-Franklin based IBE using OTATE pairing with Treshold key share based on Pedersen's VSS

## Problem Description

See Report section: _null_

## Running tests

`mvn test -e`

### Libraries

The project builds upon the following libraries.

__Expose .jars to IDE__: Add `.jar` files under `/src/main/resources/jars/../` then Right-Click
_Add as library__.

#### Junit5 libraries

* `org.junit.jupiter:junit-jupiter-api:5.10.0`
* `org.junit.jupiter:junit-jupiter-params:5.10.0`

<!-- todo: nem kell mind... -->
* `org.apiguardian:apiguardian-api:1.1.2`
* `org.junit.jupiter:junit-jupiter-engine:5.10.0`
* `org.junit.jupiter:junit-jupiter:5.10.0`
* `org.junit.platform:junit-platform-commons:1.10.0`
* `org.junit.platform:junit-platform-engine:1.10.0`
* `org.opentest4j:opentest4j:1.3.0`

#### jPBC specific libraries (TODO: change this to relic !!)

<!-- SHA256sum: 8d8bff8a3f95eb7de3e0a8285198132dd3c0ff3cfa16d1854bb9b96019207da8 -->
<!-- GOST-hash: 0d57ab521bc76a43c7a27accef336c40dce9d00c6bd1a5eb042acf47e43d0312 -->
* `.jar` file is available to download at: https://sourceforge.net/projects/jpbc/files/jpbc_2_0_0/

The specific `*.jar` can be installed after extracting the archive with: 

```bash
# Install specific file_name
mvn install:install-file \
  -Dfile=$PATH_TO_JAR/jpbc-api-2.0.0.jar \
  -DgroupId=it.unisa.dia.gas \
  # Change artifactId according to file_name
  -DartifactId=jpbc-api \
  -Dversion=2.0.0 \
  -Dpackaging=jar
```

Similalry, the `.jar` files can be imported to the local maven repository for: 

* `jpbc-api-2.0.0.jar`
* `jpbc-benchmark-2.0.0.jar`
* `jpbc-crypto-2.0.0.jar`
* `jpbc-mm-2.0.0.jar`
* `jpbc-pbc-2.0.0.jar`
* `jpbc-plaf-2.0.0.jar`

Note, for proof of concept (_before adding relic via JNI_) the 
following Java packages were added to the project, installing them 
on the host environment is _not_ necessary:

* it.unisa.dia.gas.jbpc-api
* it.unisa.dia.gas.jbpc-plaf

### BouncyCastle

<!-- Further bouncycastle versions:  -->
The `*.jar` can be downloaded from: https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.82/

---

## Implementation specific notes

### Architecture Overview

```
       +------------------------+
       | MPC/Shamir (t-of-n)    |                       <=== Uses Ed25519 for Master_seed gen
       +------------------------+                            with Pedersen VSS, 
                 |                                           HMAC-BLAKE2b
          master_seed (shared)                          
                 |
     +-----------+-------------------+                  <=== Adaptability to different
     |           |                   |                       cryptographic curve families
     v           v                   v                       (e.g. BN_XXX, BLS_XXX)
  Ed25519 SK   BN MSK             BLS MSK
  (Bouncy)     (JPBC pairing)     (JPBC pairing)
                 |
             Threshold PKG                              <=== Multi-party Computation with 
  (Partial keys from shares → reconstruct)                   Pedersen VSS, HMAC-BLAKE2b
                 |
             Boneh–Franklin IBE                         <=== IBE with OTATE pairing, BLAKE2b
       (H1(ID) → G1, d_ID = s * Q_ID)
                 |
          Encrypt / Decrypt
```


__TODO:__ Instead of `JPBC` (_outdated, use only for testing !!_) we need to use `bouncycastle` + `relic` via JNI.


### Project structure (In-Progress)

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

Java Packages:
* Client: 
  * Alice
  * Bob
* crypto:
  * BF_IBE
  * DPK
  * MPCSeedGenerator
  * ThresholdCryptography

Test suite (__In-progress__): 
* BF_IBE_ThresholdTest
* BF_IBE_UnitTest
* AliceBobTest
* AliceBobParameterizedTest


#### Classes overview  (In-Progress)

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
    * Bob reconstructs private key from threshold PKG and decrypts <- __TODO__: Bob csak akkor rekonstrualjon privat kulcsot, ha Bob == DKG eset igaz. 


The design overview:

<!-- Justifications:  efficiency + speed --->
* Ed25519 is used only for generating the master seed for MPC/Shamir.

<!-- Justification: -->
* Supports BN638 and BLS24_477 curves for Boneh–Franklin IBE.

<!-- Justifications: adaptability, flexibility, choice to use different cryptosystems --->
* Threshold PKG with partial key computation and reconstruction.

<!-- Justifications: Flexibility, get rid of classical CA + key management --->
* Alice/Bob client-server messaging using BF IBE.


### JNI wrapper for `relic-toolkit` 

## Design choices and parameter justifications  (In-Progress)

See Report section: _null_

### Pairings over BN, BLS elliptic curves

See Report section: _null_

### HMAC Key derivation function: BLAKE vs SHA256

See Report section: _null_

### Shamir's Secret Sharing + Pedersen's VSS vs. Distributed Key Protocol

See Report section: _null_
