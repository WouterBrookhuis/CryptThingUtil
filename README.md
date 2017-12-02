# CryptThingUtil

Small experiment with using mbedTLS' crypto library for file encryption.
## Features:
* AES128 GCM encryption/decryption of files
* Probably bad usage of TLS PRF function as a KDF
* Supports files up to 2^32 bytes long
* Single threaded for minimal performance