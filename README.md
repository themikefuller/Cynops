# Cynops
End-to-end Encrypted Chat and Messaging

Cynops is a custom and experimental implementation of a Triple Diffie-Hellman Key Exchange, Cryptographic Ratchet, and Sealed Envelope inspired by The [Signal Protocol](https://signal.org/docs). Users can create longlived chat sessions based on a set of initial ephemeral and longlived keys. The nature of the protocol allows for messages to be exchanged with forward and future secracy.

This library was inspired by the X3DH protocol and Double Ratchet Algorithm. It IS NOT a directly compatible implementation of these specifications. Cynops uses ECDH keys based on the secp256r1 (prime256v1) curve for key derivation. AES-GCM is used for encryption and Authentication. Cryptographic signatures are not a part of this library, though they could be implemented if desired.

This library makes use of the Web Crypto API (and the node-webcrypto-ossl package in Node) via [Starbase Cryptic](https://github.com/StarbaseAlpha/Cryptic).

The development of Cynops and Starbase Cryptic are currently entangled.
