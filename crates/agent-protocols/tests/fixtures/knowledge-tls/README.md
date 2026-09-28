These self-signed localhost certificate and private key bytes are public test
fixtures for an in-process HTTPS server. Never use this key for real services.
The test reqwest client explicitly trusts this certificate; production clients
retain ordinary certificate verification.
