=====================================================================
PROYECTO: Aplicación de escritorio segura en Java - Cooperativa COOPEVIDA
CURSO: IF-0019 Seguridad en Sistemas Informáticos, Grupo 01 (II Semestre 2026)
GRUPO DE TRABAJO: 04
=====================================================================

1. INTEGRANTES DEL GRUPO
------------------------
- José Daniel Salas Vivas — Carné: C27097
- Luis Felipe Alfaro Vargas — Carné: C30250
- Saul Esquivel Barrantes — Carné: C4E953
- Xavier Mauricio Salas Jimenez — Carné: C37129

2. VERSIONES UTILIZADAS
-----------------------
- JDK: Java 17 LTS (o superior)
- IDE: Apache NetBeans 17 o superior (probado en Apache NetBeans 31, proyecto Maven)
- Base de datos: MariaDB 10.4 o superior
- Driver JDBC: MariaDB Connector/J 3.3.3, incluido en la carpeta lib/ del proyecto
  (lib/org/mariadb/jdbc/mariadb-java-client/3.3.3/). El pom.xml lo toma de ahí,
  así que no se necesita descargarlo.

3. CONFIGURACIÓN DE CREDENCIALES Y CLAVE DE CIFRADO (R6 y R7)
-------------------------------------------------------------
Las credenciales de conexión a la base de datos y la clave de cifrado AES-256
NO se encuentran en el código fuente:
- En la raíz del proyecto se incluye el archivo de ejemplo: `config.properties.ejemplo`
- Antes de ejecutar la aplicación, copie `config.properties.ejemplo` como `config.properties`
  en la raíz del proyecto y configure:
    db.url=jdbc:mariadb://localhost:3306/coopevida
    db.user=coopevida_app
    db.password=CambieEstaClave#2026
    aes.key=<Clave AES de 256 bits (32 bytes) codificada en Base64>
- Alternativamente, la aplicación también permite leer estos valores desde las
  variables de entorno:
    COOPEVIDA_DB_URL, COOPEVIDA_DB_USER, COOPEVIDA_DB_PASS y COOPEVIDA_AES_KEY.

4. PASOS DE INSTALACIÓN Y EJECUCIÓN
-----------------------------------
Paso 1: Crear la base de datos y el usuario de mínimo privilegio:
        Ejecute el script base en MariaDB con un usuario administrador (root):
          mariadb -u root -p < coopevida_base.sql

Paso 2: Configurar `config.properties`:
        Asegúrese de que el archivo `config.properties` exista en la raíz del proyecto
        con una clave AES de 32 bytes en Base64 (por ejemplo, puede generar una con
        `openssl rand -base64 32`).

Paso 3: Abrir el proyecto en NetBeans:
        En NetBeans seleccione `File -> Open Project...` y elija la carpeta del proyecto.

Paso 4: Cargar los datos de prueba (CargaInicial):
        Ejecute una sola vez la clase `app.CargaInicial` (clic derecho -> `Run File` en
        NetBeans). Inserta los 6 usuarios con hash PBKDF2 (600 000 iteraciones y sal
        aleatoria de 16 bytes), las 5 cuentas y los 10 movimientos cifrados con AES-GCM
        (256 bits). La aplicación (`app.Main`) no carga estos datos por su cuenta.

Paso 5: Ejecutar la aplicación:
        Ejecute el proyecto en NetBeans (`Run Project` / F6), lo cual inicia `app.Main`
        y abre la ventana `LoginFrame`.

5. USUARIOS DE PRUEBA POR ROL Y CONTRASEÑAS
-------------------------------------------
Administrador:
  - Usuario: admin1       | Contraseña: Admin1-Coop#2026

Ejecutivo:
  - Usuario: ejecutivo1   | Contraseña: Ejec1-Coop#2026
  - Usuario: ejecutivo2   | Contraseña: Ejec2-Coop#2026

Asociado:
  - Usuario: asociado1    | Contraseña: Asoc1-Coop#2026  (Cédula: 112340567 - Ana Lucía Vargas Solano)
  - Usuario: asociado2    | Contraseña: Asoc2-Coop#2026  (Cédula: 205670891 - Carlos Eduardo Jiménez Arce)
  - Usuario: asociado3    | Contraseña: Asoc3-Coop#2026  (Cédula: 304560123 - María Fernanda Chaves Brenes)

Asociados sin usuario (para pruebas de vinculación y consulta):
  - Asociado 4            | Cédula: 401230456 - Luis Diego Mora Castillo (Saldo: 0.00)
  - Asociado 5            | Cédula: 503450789 - Sofía Ramírez Alfaro (Saldo: 0.00, sin movimientos)

6. DÓNDE SE CUMPLE CADA REQUISITO DE SEGURIDAD
-----------------------------------------------
En el código, cada control tiene un comentario que empieza con su requisito
(por ejemplo "// R4:"), así que basta buscar "R4" para encontrarlo.

R1  Contraseñas con PBKDF2 ........... seguridad/Cripto.java (hashContrasena, verificarContrasena)
R2  Largo mínimo y bloqueo 5 / 15 s .. servicio/Validaciones.java (validarCambioContrasena)
                                       servicio/CoopevidaServicio.java (iniciarSesion)
                                       app/LoginFrame.java (desactiva los campos)
R3  Permisos por rol ................. seguridad/ControlAcceso.java (matriz de permisos)
                                       servicio/CoopevidaServicio.java (verificarPermisoConBitacora,
                                       pertenencia en consultarCuenta)
R4  Prevención de inyección SQL ...... dao/CoopevidaDAO.java (todas las consultas con PreparedStatement)
R5  Validación por lista blanca ...... servicio/Validaciones.java
R6  Cifrado AES-GCM .................. seguridad/Cripto.java (cifrarTexto, descifrarTexto)
                                       seguridad/Configuracion.java (clave fuera del código)
R7  Mínimo privilegio en la BD ....... coopevida_base.sql (GRANT a coopevida_app)
                                       dao/CoopevidaDAO.java (obtenerConexion)
R8  Bitácora de solo inserción ....... servicio/CoopevidaServicio.java (registrarBitacoraSeguro)
                                       coopevida_base.sql (solo INSERT sobre bitacora)
R9  Sesión de 2 min y mensaje M02 .... app/MainFrame.java (verificarActividadSesion)
                                       servicio/CoopevidaServicio.java (manejarErrorTecnico)

7. DECLARACIÓN DE USO DE HERRAMIENTAS DE IA
-------------------------------------------
Se utilizó un asistente de IA como apoyo para la estructuración inicial de las
capas del proyecto, generación de plantillas Swing compatibles con el diseñador
de NetBeans y revisión de buenas prácticas de PBKDF2 y AES-GCM en `javax.crypto`.

También se utilizó Claude Code (Anthropic) para revisar el código contra el enunciado y
aplicar correcciones: límite del monto, control de retiros simultáneos, conversión de
errores inesperados al mensaje M02, saneamiento de la bitácora, separación de las clases
Validaciones y Configuracion, simplificación de comentarios e inclusión del driver JDBC.
