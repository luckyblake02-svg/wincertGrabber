import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import re
import warnings

#Just for my own sake. I kept getting warnings on one of my personal certs. This can be optionally commented out.
warnings.filterwarnings("ignore", category=UserWarning)

def graphCert():

    certList = []
    i = 0

    #Enumerate "MY" cert store on windows using ssl library. The results are 3 part objects.
    for cert_bytes, encoding_type, trust in ssl.enum_certificates("MY"):
        #Use x509 library to read in cert bytes
        cert = x509.load_der_x509_certificate(cert_bytes)
        #Grab SHA1 fingerprint using hashes library
        fingerprint_bytes = cert.fingerprint(hashes.SHA1())
        #Join everything together, set to lowercase hex (x), then zero-pad (0) 2 characters (2) for each byte
        fingerprint_hex = "".join(f"{b:02x}" for b in fingerprint_bytes)
        certList.extend([cert.subject, fingerprint_hex])

    while i < len(certList):
        #If you are looking for a specific cert
        if re.search("pattern", str(certList[i])):
            thumbprint = certList[i + 1]
        i += 2

    #Format for cert-based graph authentication
    graphProperties = {'AppID': "appid", 
                       'TenantID': "tenantid", 
                       'CertificateThumbprint': thumbprint}
    return graphProperties

print(graphCert())
