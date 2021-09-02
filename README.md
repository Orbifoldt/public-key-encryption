# public-key-encryption
Demo of PKI and how this is used for SSL certificates

Using small primes and 8-bit blocks of data we demonstrate how RSA works. RSA is an example of Public Key encryption (or Assymetrice encryption), which is used everywhere to create a secure connection.

The concept of public key encryption can be utilized for authorization. This forms the base of SSL/TLS certification which is used to form a HTTPS connection. The actual encryption of data over an such a connection does not use RSA (or any other assymetric encryption), rather it is only used initally to establish a symmetric key pair. The latter is used for the rest of the lifetime of the session. See e.g. Diffie-Hellman protocol for how to establish such a key pair over a public, unprotected connection. 
