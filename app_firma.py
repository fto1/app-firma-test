import streamlit as st
import datetime
import os
from io import BytesIO

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.pdf import cms

# Configurazione pagina Web
st.set_page_config(page_title="Firma di Test PAdES", page_icon="✍️")
st.title("✍️ Firma Digitale di Test")
st.markdown("Carica un PDF per apporre una firma digitale di collaudo (con Codice Fiscale di test).")

PASSWORD = b"password_segreta_123"
FILE_P12 = "certificato_test.p12"

# 1. Funzione per generare il certificato (eseguita solo se non esiste)
@st.cache_resource
def ottieni_certificato():
    if os.path.exists(FILE_P12):
        with open(FILE_P12, "rb") as f:
            return f.read()
            
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    codice_fiscale = "TINIT-RSSMRA80A01H501U"
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ambiente di Test SpA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Mario Rossi Test"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, codice_fiscale), 
    ])
    
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(key, hashes.SHA256())
    
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"test_cert", key=key, cert=cert, cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(PASSWORD)
    )
    
    with open(FILE_P12, "wb") as f:
        f.write(p12_data)
    return p12_data

# 2. Funzione per firmare in memoria
def firma_pdf_in_memoria(pdf_bytes, p12_data):
    private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(p12_data, PASSWORD)
    
    data_firma = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S+00\'00\'')
    metadati = {
        "sigflags": 3,
        "contact": "test@azienda.it",
        "location": "Italia",
        "reason": "Test Firma PAdES",
        "signingdate": data_firma, 
    }
    
    firma_dati = cms.sign(pdf_bytes, metadati, private_key, certificate, additional_certs or [], 'sha256')
    
    pdf_firmato = BytesIO()
    pdf_firmato.write(pdf_bytes)
    pdf_firmato.write(firma_dati)
    pdf_firmato.seek(0)
    
    return pdf_firmato

# --- INTERFACCIA UTENTE ---
p12_data = ottieni_certificato()

# Box per caricare il file
file_caricato = st.file_uploader("Trascina qui il tuo PDF", type=["pdf"])

if file_caricato is not None:
    st.success("File caricato correttamente!")
    
    if st.button("Apponi Firma Digitale", type="primary"):
        with st.spinner('Firma in corso...'):
            pdf_bytes = file_caricato.read()
            pdf_firmato_io = firma_pdf_in_memoria(pdf_bytes, p12_data)
            
            nome_originale = file_caricato.name
            nome_nuovo = nome_originale.lower().replace(".pdf", "_firmato.pdf")
            
        st.success("Operazione completata!")
        
        # Pulsante per scaricare il file firmato
        st.download_button(
            label="Scarica il PDF Firmato ⬇️",
            data=pdf_firmato_io,
            file_name=nome_nuovo,
            mime="application/pdf"
        )