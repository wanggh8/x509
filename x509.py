import json
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography import x509
with open("qq.cer", 'rb') as cert_file:
    data = cert_file.read()
    print(data)
    x = x509.load_der_x509_certificate(data, default_backend())
