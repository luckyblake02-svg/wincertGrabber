***

# wincertGrabber

`wincertGrabber` is a small **Python** utility that searches a Windows certificate store for a certificate whose subject matches a user‑supplied regular expression, then prints its SHA‑1 thumbprint. The tool is useful for quickly locating a specific certificate thumbprint by partial subject information (for example, CN, OU, or other subject fields) in interactive workflows.

## How it works

- Enumerates certificates from a specified Windows certificate store using `ssl.enum_certificates`.
- Parses each certificate as an X.509 object via the `cryptography` library (`cryptography.x509`).
- Computes the certificate’s SHA‑1 fingerprint (`thumbprint`) with `cert.fingerprint(hashes.SHA1())`.
- Converts the fingerprint bytes to a hex string and pairs it with the certificate subject.
- Uses a user‑provided regular expression to find the first subject match and returns the associated thumbprint.

> Note: The script currently assumes the certificate store exists and that at least one certificate matches the provided regex. If not, it will raise an error because `thumbprint` is never set.

## Requirements

- **Operating system**: Windows (required for `ssl.enum_certificates` access to system stores such as `MY`, `CA`, and `ROOT`).
- **Python**: 3.8+ recommended.
- **Python packages**:  
  - `cryptography` (for X.509 parsing and hashing)

Install dependencies with:

```bash
pip install cryptography
```

## Usage

1. Run the script from a terminal (PowerShell or Command Prompt):

   ```bash
   python certGrabber.py
   ```

2. When prompted:

   - Enter a **regex pattern** that will match some part of the certificate’s subject.  
     - Example: `example.com`, `CN=example`, or `.*My Internal CA.*`  
   - Enter the **certificate store name** to search, typically one of:
     - `MY`   – Personal store  
     - `CA`   – Intermediate Certification Authorities  
     - `ROOT` – Trusted Root Certification Authorities

3. The script prints the thumbprint:

   ```text
   Please enter a string that can be used to regex match the cert: example.com

   Please enter the cert store to look in (MY, CA, ROOT): MY

   The certificate thumbprint is: 12ab34cd56ef...
   ```

4. Press Enter to exit when prompted.

## Script details

Core function:

```python
def graphCert(store, reg):
    certList = []
    i = 0

    for cert_bytes, encoding_type, trust in ssl.enum_certificates(store):
        cert = x509.load_der_x509_certificate(cert_bytes)
        fingerprint_bytes = cert.fingerprint(hashes.SHA1())
        fingerprint_hex = "".join(f"{b:02x}" for b in fingerprint_bytes)
        certList.extend([cert.subject, fingerprint_hex])

    while i < len(certList):
        if re.search(reg, str(certList[i])):
            thumbprint = certList[i + 1]
        i += 2
    return thumbprint
```

- `ssl.enum_certificates(store)` yields tuples `(cert_bytes, encoding_type, trust)` from the named Windows certificate store.
- The function builds a flat list of alternating `subject`, `thumbprint` entries and searches that list with the user’s regex.

## Notes and limitations

- Only the **last matching certificate** in the store will be returned, since the loop overwrites `thumbprint` on every match; adjust if you need the first match or all matches.
- If no certificate matches the provided regex, the script will raise an `UnboundLocalError` because `thumbprint` is referenced before assignment; adding error handling for this case is recommended.
- SHA‑1 is considered weak for security purposes; here it is only used as an identifier, which is still common for Windows certificate thumbprints.
