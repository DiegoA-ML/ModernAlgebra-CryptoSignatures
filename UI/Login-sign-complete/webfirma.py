import streamlit as st # Para construir la pagina
import shutil # Para archivos
import os

# Setup de la pagina
st.set_page_config(page_title="Firma Digital de PDF", layout="centered")
st.title("Firma Digital de Documentos PDF")

# Subir el archivo
uploaded_file = st.file_uploader("Carga un archivo PDF para firmar", type=["pdf"])

if uploaded_file is not None:
    with st.spinner("Firmando el documento..."):
        input_path = os.path.join("uploads", uploaded_file.name)
        output_path = os.path.join("firmados", f"FIRMADO_{uploaded_file.name}")
        
        # Guardar archivo subido
        os.makedirs("uploads", exist_ok=True)
        os.makedirs("firmados", exist_ok=True)
        with open(input_path, "wb") as f:
            f.write(uploaded_file.read())

        # AQUI VA A ESTAR LA VERDADERA FIRMA
        shutil.copy(input_path, output_path)

        # Mostrar mensaje y botón de descarga
        st.success("Documento firmado exitosamente.")
        with open(output_path, "rb") as f:
            st.download_button(
                label="📥 Descargar documento firmado",
                data=f,
                file_name=f"FIRMADO_{uploaded_file.name}",
                mime="application/pdf"
            )
