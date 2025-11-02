Instituto Superior Técnico, Universidade de Lisboa

**Network and Computer Security**

# Cryptographic Functions in Java

Cryptography is a mathematical discipline about securing communication and data from adversaries, focusing on protocols that prevent unauthorized access.
Cryptographic functions are algorithms used for encryption, decryption, hashing, and digital signatures.
These functions can be used to ensure confidentiality, integrity, and authentication in digital interactions and information storage.

## Goals

- Utilize cryptographic mechanisms available in the Java platform;
- Demonstrate secure handling of sensitive data through encryption, decryption, hashing, digital signatures, and key management operations.

## Introduction

This is a code module that contains utility classes and unit tests of the Java Cryptography API.  
The code includes symmetric cryptography, asymmetric cryptography, digest functions and signatures.

## Demonstration

To run the default example using the execution plug-in:

```sh
mvn compile exec:java
```

## Utilities

In the `src/main/java` folder you can find some utility classes:

- *ListAlgorithms* presents the (long) list of available security providers and the cryptographic algorithms that they implement.

- The *SymKey* and *AsymKeys* examples show how to read and write cryptographic keys to and from files.

- *SecureRandomNumber* generates random numbers that are unpredictable (contrary to pseudo-random number generators).
The numbers are printed as hexadecimal values.

To run a specific example, select the profile with -P:

```sh
mvn exec:java -P list-algos
```

To list available profiles (one for each example):

```sh
mvn help:all-profiles
```

## Tests

In the `src/test/java` folder you can find unit tests for the most important cryptographic primitives:

- *SymCrypto* generates a key and uses it to cipher and decipher data with a symmetric cipher.

- *AsymCrypto* generates a key pair and uses the public key to cipher and the private key to decipher data (and then the other way around).

- *Digest* creates a cryptographic hash.

- *MAC (Message Authentication Code)* shows data integrity verification with symmetric keys.

- *Digital Signature* shows data signing and verification with asymmetric keys.

- *XMLCrypto* shows how to insert and retrieve cipher text in XML documents using base-64 encoding to represent bytes as text.
Similar techniques can applied to other text-based formats, like JSON.

To compile and execute all tests:

```sh
mvn test
```

To execute a specific test suite:

```sh
mvn test -Dtest=AsymCryptoTest
```

To execute a specific test:

```sh
mvn test -Dtest=AsymCrypto*#testCipherPublicDecipherPrivate
```

# Lab Guide

Now that you are familiar with the code structure is time to look at what it does in detail.
This guide provides an in-depth analysis of cryptographic concepts and their practical implementation in Java.
There are three key areas: symmetric cryptography, asymmetric cryptography, and integrity protection.

## Symmetric Cryptography

Symmetric cryptography in this project is implemented using AES in ECB mode with PKCS5 Padding.
AES operates with a block size of 128 bits (16 bytes).
[ECB mode ciphers each block independently](img/ECB.png).
PKCS5 Padding ensures that the overall data size is a multiple of 16 bytes.

The `SymCryptoTest` class demonstrates these concepts, focusing on key generation, encryption and decryption. Notably, the `testSymCrypto` method provides a comprehensive look at these operations. `KeyGenerator` is employed for creating AES keys, illustrating key aspects of symmetric encryption in Java.

### More about AES

Advanced Encryption Standard (AES) is a symmetric block cipher adopted globally for secure data encryption.
AES allows for key sizes of 128, 192, or 256 bits, with the number of encryption rounds being 10, 12, or 14 rounds, respectively, for these key sizes.
It consistently encrypts data in fixed-size blocks of 128 bits, regardless of the key size used.
Its architecture is designed to be resistant to various cryptanalytic attacks, making AES a robust and reliable choice for safeguarding sensitive information.
The consistency in block size ensures uniformity in processing data blocks, contributing to its efficiency.

## Asymmetric Cryptography

Asymmetric cryptography in this project is demonstrated using the RSA algorithm, which involves a public key for encryption and a private key for decryption, or vice versa.

The `AsymCryptoTest` class emphasizes key pair generation, encryption/decryption processes, and result validation.
The `testCipherPublicDecipherPrivate` and `testCipherPrivateDecipherPublic` methods offer practical insights into RSA's application, showcasing how public and private keys interact in data encryption and decryption.

### More about RSA

RSA, named after Rivest, Shamir, and Adleman, is a widely used asymmetric cryptographic algorithm.
It relies on the mathematical properties of large prime numbers for secure data transmission.
In RSA, data is encrypted with a public key and decrypted with a private key, making it ideal for secure communication over untrusted networks. RSA's security relies on the computational difficulty of factoring large integers, a process that becomes exponentially harder as the size of the primes increases.
It is commonly used for secure data exchange and digital signatures but not for large data encryption.

In RSA cryptography, the block size is not fixed like in AES but is determined by the key size.
For a 2048-bit RSA key, the maximum data size that can be encrypted is just under 2048 bits, reduced slightly due to padding needs.
Padding means that the actual plaintext size encrypted per block is slightly less than the key size.
Thus, the RSA block size varies based on the padding scheme and specific implementation, typically being slightly smaller than the key size.

## Integrity Protection

The project addresses integrity protection through hashing, MACs, and digital signatures:

- `DigestTest` utilizes SHA-256 to create message digests, focusing on the use of `MessageDigest` and the validation of hash outputs.
Hashes are integral to MAC and digital signature techniques but do not guarantee integrity by themselves;

- `MACTest` explores the generation and verification of MACs using HmacSHA256.
Key methods, such as `testMACObject` and `testSignatureStepByStep`, demonstrate how a secret is used to create and verify a MAC;

- In `DigitalSignatureTest`, RSA combined with SHA256 is used for signing and verifying data.
This class shows the signing of data with a private key and its verification with the public key.

These methods ensure data integrity but not authenticity without metadata to provide freshness.

## Practical Exercises

Each of the following exercises aims to deepen the understanding of cryptographic principles and their practical applications, encouraging experimentation and critical analysis of security mechanisms.

### 1. Switch the Cipher Mode of AES to CBC

[CBC (Cipher Block Chaining) ciphers each block of plain data XORed with the previous ciphered data](img/CBC.png).  
This has a significant advantage over ECB: plain data pattern obfuscation.

Implement CBC mode by modifying the `SymCryptoTest` class.
This involves creating a random Initialization Vector (IV) for each encryption session and managing it appropriately during decryption.

Use a repeated pattern in the input data, like `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`  
and compare the output of the cipher using [ECB](img/ECB.png) and [CBC](img/CBC.png) modes.

### 2. Test the Tamper Detection of either the MAC or the Digital Signature

Investigate the effectiveness of MAC or digital signature in detecting data tampering.
Intentionally modify the protected data and confirm that the verification code accurately detects the alteration.
This exercise underscores the importance of integrity checks in cryptographic systems: it is not enough to add the MAC or signature, but it must also be verified in a robust way.

### 3. Add Freshness to either the MAC or the Digital Signature

Incorporate a freshness element, a nonce (*number used once*), to provide replay attack detection in either the MAC or digital signature code.
Experiment with unique message numbers or timestamps as nonces.
Assess how each approach might be vulnerable to specific types of attacks, and consider strategies to mitigate these vulnerabilities.
This exercise emphasizes the significance of freshness in detecting replay attacks.

### 4. Measure the operation times

Record the operation times for key generation, encryption, and decryption.
In Java, you can use `System.currentTimeMillis()` to get the current time in milliseconds as a value of type `long`.

Compare symmetric (AES) and asymmetric (RSA) operations for the same size of input data.
Compile the results in a table to contrast the efficiency of symmetric and asymmetric cryptography in terms of processing speed.

### 5. Docs
- [Cipher](https://docs.oracle.com/javase/8/docs/api///?javax/crypto/Cipher.html)
- [IvParameterSpec](https://docs.oracle.com/javase/8/docs/api/index.html?javax/crypto/spec/IvParameterSpec.html)
 


----

[SIRS Faculty](mailto:meic-sirs@disciplinas.tecnico.ulisboa.pt)
