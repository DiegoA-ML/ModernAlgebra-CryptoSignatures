# firma_digital.py
import asyncio
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.keys import load_cert_from_pemder
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
import io

# Paths fijos (ajústalos si cambian)
PRIVATE_KEY_PATH = "/Users/mauriciovg/Crypto/private.key"
CERTIFICATE_PATH = "/Users/mauriciovg/Crypto/certificate.pem"

def cargar_firmante():
    return signers.SimpleSigner.load(
        PRIVATE_KEY_PATH, CERTIFICATE_PATH, key_passphrase=None
    )

async def firmar_pdf(pdf_bytes: bytes) -> bytes:
    cms_signer = cargar_firmante()
    pdf_stream = io.BytesIO(pdf_bytes)
    writer = IncrementalPdfFileWriter(pdf_stream)
    signed = await signers.async_sign_pdf(
        writer,
        signers.PdfSignatureMetadata(field_name="Signature1"),
        signer=cms_signer,
    )
    return signed.getvalue()

def validar_pdf(pdf_bytes: bytes) -> str:
    root_cert = load_cert_from_pemder(CERTIFICATE_PATH)
    vc = ValidationContext(trust_roots=[root_cert])
    reader = PdfFileReader(io.BytesIO(pdf_bytes))
    sig = reader.embedded_signatures[0]
    status = validate_pdf_signature(sig, vc)
    return status.pretty_print_details()

