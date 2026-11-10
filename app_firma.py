import streamlit as st
import datetime
import base64
import streamlit.components.v1 as components
from io import BytesIO

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.pdf import cms

st.set_page_config(page_title="Firma Digitale di Test", page_icon="✍️", layout="centered")

st.title("✍️ Firma Digitale di Test (PAdES)")
st.markdown("Personalizza i dati del firmatario, carica il file e scarica il PDF firmato.")

# --- SEZIONE 1: DATI DEL FIRMATARIO ---
st.subheader("1. Dati del Firmatario")

col1, col2 = st.columns(2)
with col1:
    nome = st.text_input("Nome", value="Mario")
with col2:
    cognome = st.text_input("Cognome", value="Rossi")

codice_fiscale = st.text_input("Codice Fiscale", value="RSSMRA80A01H501U", max_chars=16)

def genera_certificato_dinamico(nome, cognome, cf, password):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    cf_clean = cf.strip().upper()
    cf_formatted = cf_clean if cf_clean.startswith("TINIT-") else f"TINIT-{cf_clean}"
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ambiente di Test SpA"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{nome.strip()} {cognome.strip()}"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, cf_formatted), 
    ])
    
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(key, hashes.SHA256())
    
    return pkcs12.serialize_key_and_certificates(
        name=b"test_cert", key=key, cert=cert, cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

def firma_pdf_in_memoria(pdf_bytes, p12_bytes, password):
    private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(p12_bytes, password)
    
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
    return pdf_firmato.getvalue()

def avvia_download_automatico(pdf_bytes, nome_file):
    b64 = base64.b64encode(pdf_bytes).decode('utf-8')
    js_code = f"""
        <a id="auto-download" href="data:application/pdf;base64,{b64}" download="{nome_file}"></a>
        <script>
            document.getElementById('auto-download').click();
        </script>
    """
    components.html(js_code, height=0, width=0)

# --- SEZIONE 2: UPLOAD & FIRMA ---
st.subheader("2. Carica e Firma Documento")

file_caricato = st.file_uploader("Trascina qui il file PDF o clicca per sfogliare", type=["pdf"])

if file_caricato is not None:
    if not codice_fiscale or len(codice_fiscale.strip()) < 11:
        st.warning("⚠️ Inserisci un Codice Fiscale valido prima di firmare.")
    else:
        if st.button("✍️ Firma e Scarica PDF", type="primary", use_container_width=True):
            with st.spinner('Generazione certificato e firma del PDF in corso...'):
                password = b"password_test_123"
                
                p12_bytes = genera_certificato_dinamico(nome, cognome, codice_fiscale, password)
                pdf_bytes = file_caricato.read()
                pdf_firmato_bytes = firma_pdf_in_memoria(pdf_bytes, p12_bytes, password)
                
                nome_originale = file_caricato.name
                nome_nuovo = nome_originale.lower().replace(".pdf", "_firmato.pdf")
                
            st.success("✅ Firma applicata con successo! Il download dovrebbe avviarsi automaticamente.")
            
            avvia_download_automatico(pdf_firmato_bytes, nome_nuovo)
            
            st.download_button(
                label="Se il download non parte, clicca qui per scaricare ⬇️",
                data=pdf_firmato_bytes,
                file_name=nome_nuovo,
                mime="application/pdf"
            )
