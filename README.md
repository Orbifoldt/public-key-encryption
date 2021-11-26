# public-key-encryption
Demo of PKI and how this is used for creating SSL certificates and certification authorities (CA).

Using small primes and 8-bit blocks of data we demonstrate how RSA works. RSA is an example of Public Key encryption (or Asymmetric encryption), which is used everywhere to create a secure connection.

The concept of public key encryption can be utilized for authorization, which we also demonstrate in this code sample. We create some certificates and a Certification Authority, and demonstrate how this CA can sign a certificate and how you as a client can verify this signature. 

These concepts form the base of SSL (i.e. TLS) certification which is used to form a HTTPS connection. The actual encryption of data over such a connection does not use RSA (or any other assymetric encryption), rather it is only used initally to establish a symmetric key pair. The latter is used for the rest of the lifetime of the session. See e.g. Diffie-Hellman protocol for how to establish such a key pair over a public, unprotected connection. 

## Generating real keys
Nice to note is that you can easily generate real-life key pairs using openssl. Below commands will generate a key pair such that the modulus `n` is a 2048-bit integer:
````shell
openssl genrsa -out key.key 2048
openssl rsa -text -in key.key
````
