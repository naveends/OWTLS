These are the command I used to generate the SSL certificates:

openssl genrsa -out bob.key 1024
openssl pkcs8 -topk8 -inform PEM -outform DER -in bob.key -out bob.key8 -nocrypt
openssl req -new -key bob.key -out bob.csr
openssl x509 -req -days 365 -in bob.csr -signkey bob.key -out bob.crt

openssl x509 -in bob.crt -inform PEM -out bob.der -outform DER

Alice and Bob each use their self-signed certificates for the SSL communication.