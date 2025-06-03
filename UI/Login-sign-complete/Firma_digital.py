# From scratch implementation EC signature embedded in PDF metadata
# Authors: Asgard Andrés Mendoza Flores <br> Diego Gutiérrez Vargas

import asyncio
import nest_asyncio
nest_asyncio.apply()

# Import necessary libraries
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter


# Firma de documentos
# 1. Carga de las llaves

# En un caso real se debería usar un archivo de clave privada proporcionado por el socio
private_key_path = r"/Users/mauriciovg/Crypto/private.key"

# Load the private key from file
with open(private_key_path, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None  # If your key has a password, provide it here
    )

# Convert the private key to PEM format
pem = private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.TraditionalOpenSSL,
   encryption_algorithm=serialization.NoEncryption()
)

# Print the private key in PEM format
pem.splitlines()

# 2. Generación de la firma

# Cargar el archivo PDF que se va a firmar
pdf_path = r"/Users/mauriciovg/Crypto/CONTRATO DE APROBACIÓN DIGITAL DE COMPRAS CASA MONARCA.pdf"

# Leer el archivo PDF
with open(pdf_path, "rb") as f:
    pdf_data = f.read()

# Generar la firma con la clave privada
signature = private_key.sign(
    pdf_data,
    ec.ECDSA(hashes.SHA256())
)

# 3. Embedding de la firma al archivo

async def async_demo(signer, fname):
    with open(fname, 'rb') as doc:
        w = IncrementalPdfFileWriter(doc)
        out = await signers.async_sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Signature1'),
            signer=signer,
        )

        return out

# Cargar el firmante (firmante simple)
cms_signer = signers.SimpleSigner.load(
    r"/Users/mauriciovg/Crypto/private.key", r"/Users/mauriciovg/Crypto/certificate.pem",    
    key_passphrase=None
)

# Firmar el archivo PDF
signed_pdf = asyncio.run(async_demo(cms_signer, pdf_path))

# Guardar el PDF firmado en un nuevo archivo
signed_pdf_path = r"/Users/mauriciovg/Crypto/Documento_Firmado.pdf"
with open(signed_pdf_path, 'wb') as f:
    f.write(signed_pdf.getvalue())

# Validación de firma del archivo firmado

from pyhanko.keys import load_cert_from_pemder
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature

# Cargar el certificado raíz desde el archivo PEM
root_cert = load_cert_from_pemder(r"/Users/mauriciovg/Crypto/certificate.pem")

# Crear el contexto de validación con el certificado raíz
vc = ValidationContext(trust_roots=[root_cert])

# Validar la firma del documento PDF firmado
with open(signed_pdf_path, 'rb') as doc:
    r = PdfFileReader(doc)
    sig = r.embedded_signatures[0]
    status = validate_pdf_signature(sig, vc)
    print(status.pretty_print_details())
