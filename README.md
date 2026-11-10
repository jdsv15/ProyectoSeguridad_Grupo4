PROYECTO: Aplicación de escritorio segura en Java - Cooperativa COOPEVIDA
CURSO: IF-0019 Seguridad en Sistemas Informáticos, Grupo 04 (II Semestre 2026)

1. INTEGRANTES DEL GRUPO
------------------------
- José Daniel Salas Vivas — Carné: C27097
-  Luis Felipe Alfaro Vargas — Carné: C30250
- Saul Esquivel Barrantes — Carné: C4E953
- Xavier Mauricio Salas Jimenez — Carné: C37129

2. VERSIONES UTILIZADAS
-----------------------
- JDK: Java 17 LTS (o superior)
- IDE: Apache NetBeans 17 o superior (probado en Apache NetBeans 31, proyecto Maven)
- Base de datos: MariaDB 10.4 o superior
- Driver JDBC: MariaDB Connector/J 3.3.3 (declarado en pom.xml)

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
        - Puede ejecutar la clase `app.CargaInicial` (`Run File` en NetBeans), la cual
          inserta los 6 usuarios con hash PBKDF2 (600 000 iteraciones y sal aleatoria de
          16 bytes), las 5 cuentas y los 10 movimientos cifrados con AES-GCM (256 bits).
        - También, al ejecutar `app.Main` por primera vez, si la tabla `usuario` está
          vacía, `CargaInicial` se ejecuta automáticamente.

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

6. DECLARACIÓN DE USO DE HERRAMIENTAS DE IA
-------------------------------------------
Se utilizó un asistente de IA como apoyo para la estructuración inicial de las
capas del proyecto, generación de plantillas Swing compatibles con el diseñador
de NetBeans y revisión de buenas prácticas de PBKDF2 y AES-GCM en `javax.crypto`.
