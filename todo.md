# ToDo List

## Statistics
- Issuers
    - Gather data on who the top 10-15 issuers were
    - Create graph
- Duplicate Keys
    - Who are the issuers
    - Overlapping Validity
        - Who creates these keys. Does one CA generate these disproportionately?
    - Changed issuer
        - What aspects of the issuer change?
        - Exclude issuers whose name changes minorly (i.e. 2009 vs 2010)
- Organizations
    - Including CAs
    - Excluding CAs (so real companies only)
    
## Fingerprinting
- Fingerprint each company's keys
- Fingerprint each CA's keys
    - NOTE: this could be invalid b/c we don't know the keys were generated with the same fingerprinting algorithms

Weakness: Assumes the CA generates the key itself. If the company gives key (using arbitrary algorithm) to CA to certify,
then don't know what method they used to generate.

    
## Cryptographic Weaknesses
- Examine RSA key that was bad
- Explain why using DSA keys is weak, but not particularly harmful