import streamlit as st
import asyncio
import nest_asyncio
from firma_documentos import firmar_pdf, validar_pdf

nest_asyncio.apply()
st.set_page_config(page_title="Login + Firma Digital", layout="centered")

# --- Mostrar banner centrado ---
# st.image("/Users/mauriciovg/Crypto/banner.png", use_container_width=True)

# --- Mostrar logo centrado debajo ---
st.image("/Users/mauriciovg/Crypto/logo.png")  # Ajusta el tamaño si quieres

# --- Estado inicial ---
if "login_exitoso" not in st.session_state:
    st.session_state.login_exitoso = False

# --- Función login ---
def login_interface():
    st.title("Creación de Cuenta")

    with st.expander("Registrar cuenta", expanded=True):
        email = st.text_input("Correo Electrónico")
        password = st.text_input("Contraseña", type="password")
        confirm_password = st.text_input("Confirmar Contraseña", type="password")

        certificado = st.file_uploader("Certificado", type=["pdf", "pem"])
        llave = st.file_uploader("Llave", type=["pdf", "key"])

        if st.button("Continuar a la firma digital"):
            if not email or not password or not confirm_password:
                st.warning("Por favor, complete todos los campos.")
            elif password != confirm_password:
                st.warning("Las contraseñas no coinciden.")
            elif not certificado or not llave:
                st.error("Sube ambos archivos requeridos.")
            else:
                st.success("Cuenta creada exitosamente.")
                st.session_state.login_exitoso = True
                st.rerun()

# --- Función firma digital ---
def firma_interface():
    st.title("Herramienta de Firma Digital de Documentos PDF")

    uploaded_file = st.file_uploader("Carga un archivo PDF para firmar y validar", type=["pdf"])

    if "signed_pdf_bytes" not in st.session_state:
        st.session_state["signed_pdf_bytes"] = None

    if uploaded_file:
        pdf_bytes = uploaded_file.read()

        if st.button("Firmar PDF"):
            with st.spinner("Firmando documento..."):
                try:
                    signed_bytes = asyncio.run(firmar_pdf(pdf_bytes))
                    st.session_state["signed_pdf_bytes"] = signed_bytes
                    st.success("✅ Documento firmado exitosamente.")
                    st.download_button(
                        label="📥 Descargar PDF firmado",
                        data=signed_bytes,
                        file_name=f"FIRMADO_{uploaded_file.name}",
                        mime="application/pdf"
                    )
                except Exception as e:
                    st.error(f"❌ Error al firmar: {str(e)}")

        if st.button("Validar firma"):
            with st.spinner("Validando firma..."):
                try:
                    bytes_to_validate = st.session_state["signed_pdf_bytes"] or pdf_bytes
                    resultado = validar_pdf(bytes_to_validate)
                    st.text_area("Resultado de validación", resultado, height=300)
                except IndexError:
                    st.error("❌ No se encontró ninguna firma en el documento.")
                except Exception as e:
                    st.error(f"❌ Error al validar: {str(e)}")

# --- Lógica principal ---
if st.session_state.login_exitoso:
    firma_interface()
else:
    login_interface()
