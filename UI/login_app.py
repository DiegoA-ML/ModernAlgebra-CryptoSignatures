import streamlit as st

# Función para mostrar el formulario de inicio de sesión y drag & drop
def login_interface():
    st.title("Formulario de Creación de Cuenta")

    # Mostrar el popup (simulado) de registro al presionar un botón
    with st.expander("Registrar cuenta", expanded=True):
        # Campos de email, contraseña y confirmar contraseña
        email = st.text_input("Correo Electrónico")
        password = st.text_input("Contraseña", type="password")
        confirm_password = st.text_input("Confirmar Contraseña", type="password")

        # Verificar que los campos no estén vacíos
        if not email or not password or not confirm_password:
            st.warning("Por favor, llene todos los campos para continuar.")
        elif password != confirm_password:
            st.warning("Las contraseñas no coinciden. Intenta nuevamente.")
        else:
            st.success("Correo y contraseñas registradas correctamente.")

    # Mostrar los datos ya ingresados en el formulario
    if email and password == confirm_password:
        st.write(f"Correo Electrónico registrado: {email}")
        st.write("Contraseña registrada: ****")  # Se oculta la contraseña por seguridad

    # Elementos de Drag & Drop para cargar los archivos
    st.subheader("Sube los archivos necesarios")
    certificado = st.file_uploader("Certificado", type=["pdf", "jpg", "png"])
    llave = st.file_uploader("Llave", type=["pdf", "jpg", "png"])

    # Botón para crear cuenta
    if st.button("Crear Cuenta"):
        # Verificar si todos los campos están completos y los archivos fueron subidos
        if email and password == confirm_password and certificado and llave:
            st.success("Cuenta creada exitosamente. ¡Bienvenido!")
        else:
            st.error("Por favor, asegúrate de llenar todos los campos y subir los archivos necesarios.")

# Llamar a la función
login_interface()
