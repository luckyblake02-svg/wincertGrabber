import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import re
import warnings
import time

#Completely optional. I got tired of seeing deprecation errors.
warnings.filterwarnings("ignore", category=UserWarning)

def graphCert(store, reg):

    certList = []
    i = 0

    #Reading in certs via ssl enum certs is 3 parts: Bytes, encoding, and trust.
    for cert_bytes, encoding_type, trust in ssl.enum_certificates(store):
        cert = x509.load_der_x509_certificate(cert_bytes)
        #Get the fingerprint bytes
        fingerprint_bytes = cert.fingerprint(hashes.SHA1())
        #Convert to lowercase hex (x), zero-pad to two characters (02).
        fingerprint_hex = "".join(f"{b:02x}" for b in fingerprint_bytes)
        certList.extend([cert.subject, fingerprint_hex])

    while i < len(certList):
        #Regex search for string to locate the exact cert
        if re.search(reg, str(certList[i])):
            thumbprint = certList[i + 1]
        i += 2
    return thumbprint

#What to find
wtf = input("Please enter a string that can be used to regex match the cert: ")
print()
certStore = input("Please enter the cert store to look in (MY, CA, ROOT): ")
print()

print(f"The certificate thumbprint is: {graphCert(certStore, wtf)}")
time.sleep(5)
