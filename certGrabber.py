import ssl #ssl library for certs
from cryptography import x509 #x509 library for certs
from cryptography.hazmat.primitives import hashes #hash library
import re #regex library
import warnings #warnings library for suppression

warnings.filterwarnings("ignore", category=UserWarning) #this warning would not go away, so I suppressed it

def graphCert(store, reg):

    certList = []
    i = 0

    for cert_bytes, encoding_type, trust in ssl.enum_certificates(store): #ssl enum certs reads in 3 values by default
        cert = x509.load_der_x509_certificate(cert_bytes) #load bytes of cert
        fingerprint_bytes = cert.fingerprint(hashes.SHA1()) #hash the bytes to get the fingerprint
        fingerprint_hex = "".join(f"{b:02x}" for b in fingerprint_bytes) #convert fingerprint to hex
        certList.extend([cert.subject, fingerprint_hex]) #append subject and fingerprint to array

    while i < len(certList):
        if re.search(reg, str(certList[i])): #if user-inputted string is a match, store this cert
            thumbprint = certList[i + 1]
        i += 2
    return thumbprint

wtf = input("Please enter a string that can be used to regex match the cert: ") #what to find
print()
certStore = input("Please enter the cert store to look in (MY, CA, ROOT): ")
print()

print(f"The certificate thumbprint is: {graphCert(certStore, wtf)}")
print()
input("Press enter to exit...")
