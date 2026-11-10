package seguridad;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Componente central de criptografía de COOPEVIDA.
 * <ul>
 *   <li><b>R1 (Contraseñas):</b> Hash y verificación mediante {@code PBKDF2WithHmacSHA256}
 *       con 600 000 iteraciones y sal aleatoria de 16 bytes única por usuario.</li>
 *   <li><b>R6 (Datos sensibles):</b> Cifrado autenticado {@code AES/GCM/NoPadding} con
 *       clave de 256 bits leída fuera del código fuente, IV aleatorio de 12 bytes
 *       único por registro y etiqueta de autenticación de 128 bits.</li>
 *   <li><b>Generación de contraseña inicial:</b> Contraseña aleatoria de 14 caracteres
 *       con mayúsculas, minúsculas, números y símbolos usando {@link SecureRandom}.</li>
 * </ul>
 */
public final class Cripto {

    // Parámetros PBKDF2 (Requisito R1)
    private static final String ALGORITMO_PBKDF2 = "PBKDF2WithHmacSHA256";
    public static final int ITERACIONES_PBKDF2 = 600_000;
    private static final int LONGITUD_SAL_BYTES = 16;
    private static final int LONGITUD_HASH_BITS = 256;

    // Parámetros AES-GCM (Requisito R6)
    private static final String ALGORITMO_AES_GCM = "AES/GCM/NoPadding";
    private static final int LONGITUD_IV_BYTES = 12;
    private static final int LONGITUD_TAG_BITS = 128;
    private static final int LONGITUD_CLAVE_AES_BYTES = 32; // 256 bits

    // Alfabetos para generación de contraseña inicial de 14 caracteres
    private static final String MAYUSCULAS = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final String MINUSCULAS = "abcdefghijkmnopqrstuvwxyz";
    private static final String NUMEROS = "23456789";
    private static final String SIMBOLOS = "#$%&*+-=@!?";
    private static final String TODOS_CARACTERES = MAYUSCULAS + MINUSCULAS + NUMEROS + SIMBOLOS;
    private static final int LONGITUD_CLAVE_INICIAL = 14;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Hash ficticio precalculado al iniciar la clase para igualar el tiempo de
     * respuesta cuando se intenta iniciar sesión con un usuario que no existe.
     */
    private static final String HASH_FICTICIO = generarHashFicticio();

    private Cripto() {
        // Clase utilitaria no instanciable
    }

    /**
     * Genera el hash PBKDF2 (R1) de una contraseña con sal aleatoria de 16 bytes
     * y 600 000 iteraciones.
     * <p>
     * Formato almacenado: {@code iteraciones:base64(sal):base64(hash)}
     *
     * @param contrasena Contraseña en caracteres.
     * @return Cadena con iteraciones, sal y hash codificados en Base64.
     */
    public static String hashContrasena(char[] contrasena) {
        if (contrasena == null || contrasena.length == 0) {
            throw new IllegalArgumentException("La contraseña no puede estar vacía.");
        }
        byte[] sal = new byte[LONGITUD_SAL_BYTES];
        SECURE_RANDOM.nextBytes(sal);

        byte[] hash = calcularPBKDF2(contrasena, sal, ITERACIONES_PBKDF2, LONGITUD_HASH_BITS);
        String salB64 = Base64.getEncoder().encodeToString(sal);
        String hashB64 = Base64.getEncoder().encodeToString(hash);
        return ITERACIONES_PBKDF2 + ":" + salB64 + ":" + hashB64;
    }

    /**
     * Verifica si una contraseña coincide con el hash PBKDF2 almacenado (R1),
     * utilizando comparación en tiempo constante ({@link MessageDigest#isEqual}).
     *
     * @param contrasena     Contraseña ingresada por el usuario.
     * @param hashAlmacenado Hash almacenado en la columna {@code hash_contrasena}.
     * @return {@code true} si la contraseña coincide; {@code false} en caso contrario.
     */
    public static boolean verificarContrasena(char[] contrasena, String hashAlmacenado) {
        if (contrasena == null || hashAlmacenado == null || hashAlmacenado.isBlank()) {
            return false;
        }
        String[] partes = hashAlmacenado.trim().split(":");
        if (partes.length != 3) {
            return false;
        }
        try {
            int iteraciones = Integer.parseInt(partes[0]);
            if (iteraciones < ITERACIONES_PBKDF2) {
                return false;
            }
            byte[] sal = Base64.getDecoder().decode(partes[1]);
            byte[] hashEsperado = Base64.getDecoder().decode(partes[2]);

            byte[] hashCalculado = calcularPBKDF2(contrasena, sal, iteraciones, hashEsperado.length * 8);
            return MessageDigest.isEqual(hashCalculado, hashEsperado);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Ejecuta una verificación PBKDF2 completa contra un hash ficticio cuando
     * el nombre de usuario no existe en la base de datos, evitando ataques de
     * enumeración de usuarios por tiempos de respuesta (timing attack).
     */
    public static void verificarContrasenaFicticia(char[] contrasena) {
        char[] entrada = (contrasena != null && contrasena.length > 0)
                ? contrasena
                : "clave_ficticia_temporal".toCharArray();
        verificarContrasena(entrada, HASH_FICTICIO);
    }

    private static byte[] calcularPBKDF2(char[] contrasena, byte[] sal, int iteraciones, int bits) {
        PBEKeySpec spec = new PBEKeySpec(contrasena, sal, iteraciones, bits);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITMO_PBKDF2);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Error en algoritmo PBKDF2", e);
        } finally {
            spec.clearPassword();
        }
    }

    private static String generarHashFicticio() {
        return hashContrasena("ContrasenaFicticia#2026".toCharArray());
    }

    /**
     * Cifra un monto o saldo ({@link BigDecimal}) utilizando AES-GCM con clave de
     * 256 bits e IV aleatorio de 12 bytes único por operación (R6).
     * <p>
     * El arreglo devuelto tiene el formato: {@code IV (12 bytes) || texto_cifrado || tag_GCM (16 bytes)},
     * tal como lo define la columna {@code VARBINARY(64)} en {@code coopevida_base.sql}.
     *
     * @param valor Monto o saldo a cifrar.
     * @return Arreglo de bytes con IV, texto cifrado y etiqueta de autenticación.
     */
    public static byte[] cifrar(BigDecimal valor) {
        if (valor == null) {
            throw new IllegalArgumentException("El valor a cifrar no puede ser nulo.");
        }
        return cifrarTexto(valor.toPlainString());
    }

    /**
     * Descifra un arreglo de bytes cifrado con AES-GCM y lo convierte en {@link BigDecimal} (R6).
     * Verifica automáticamente la etiqueta de autenticación GCM de 128 bits.
     *
     * @param datosCifrados Bytes almacenados en la columna {@code VARBINARY(64)}.
     * @return Valor numérico exacto en {@link BigDecimal}.
     */
    public static BigDecimal descifrar(byte[] datosCifrados) {
        String texto = descifrarTexto(datosCifrados);
        try {
            return new BigDecimal(texto);
        } catch (NumberFormatException e) {
            throw new IllegalStateException("El dato descifrado no tiene un formato numérico válido", e);
        }
    }

    /**
     * Cifra una cadena en claro con AES-GCM (256 bits).
     */
    public static byte[] cifrarTexto(String textoEnClaro) {
        if (textoEnClaro == null) {
            throw new IllegalArgumentException("El texto a cifrar no puede ser nulo.");
        }
        try {
            SecretKey clave = obtenerClaveAES();
            byte[] iv = new byte[LONGITUD_IV_BYTES];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITMO_AES_GCM);
            GCMParameterSpec spec = new GCMParameterSpec(LONGITUD_TAG_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, clave, spec);

            byte[] cifradoConTag = cipher.doFinal(textoEnClaro.getBytes(StandardCharsets.UTF_8));

            ByteBuffer buffer = ByteBuffer.allocate(LONGITUD_IV_BYTES + cifradoConTag.length);
            buffer.put(iv);
            buffer.put(cifradoConTag);
            return buffer.array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Error al cifrar datos con AES-GCM", e);
        }
    }

    /**
     * Descifra un arreglo {@code IV || texto_cifrado || tag} con AES-GCM (256 bits).
     */
    public static String descifrarTexto(byte[] datosCifrados) {
        // Mínimo: 12 bytes de IV + 1 byte de dato + 16 bytes de etiqueta GCM = 29 bytes
        if (datosCifrados == null || datosCifrados.length < LONGITUD_IV_BYTES + (LONGITUD_TAG_BITS / 8) + 1) {
            throw new IllegalStateException("Datos cifrados inválidos o corruptos");
        }
        try {
            SecretKey clave = obtenerClaveAES();
            byte[] iv = Arrays.copyOfRange(datosCifrados, 0, LONGITUD_IV_BYTES);
            byte[] cifradoConTag = Arrays.copyOfRange(datosCifrados, LONGITUD_IV_BYTES, datosCifrados.length);

            Cipher cipher = Cipher.getInstance(ALGORITMO_AES_GCM);
            GCMParameterSpec spec = new GCMParameterSpec(LONGITUD_TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, clave, spec);

            byte[] textoBytes = cipher.doFinal(cifradoConTag);
            return new String(textoBytes, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Error al descifrar o verificar autenticidad AES-GCM", e);
        }
    }

    /**
     * Genera una contraseña inicial aleatoria de 14 caracteres con letras mayúsculas,
     * letras minúsculas, números y símbolos utilizando {@link SecureRandom}.
     */
    public static String generarContrasenaInicial() {
        char[] clave = new char[LONGITUD_CLAVE_INICIAL];
        // Garantizar al menos un carácter de cada categoría requerida
        clave[0] = MAYUSCULAS.charAt(SECURE_RANDOM.nextInt(MAYUSCULAS.length()));
        clave[1] = MINUSCULAS.charAt(SECURE_RANDOM.nextInt(MINUSCULAS.length()));
        clave[2] = NUMEROS.charAt(SECURE_RANDOM.nextInt(NUMEROS.length()));
        clave[3] = SIMBOLOS.charAt(SECURE_RANDOM.nextInt(SIMBOLOS.length()));

        for (int i = 4; i < LONGITUD_CLAVE_INICIAL; i++) {
            clave[i] = TODOS_CARACTERES.charAt(SECURE_RANDOM.nextInt(TODOS_CARACTERES.length()));
        }

        // Mezclar posiciones con Fisher-Yates usando SecureRandom
        for (int i = clave.length - 1; i > 0; i--) {
            int j = SECURE_RANDOM.nextInt(i + 1);
            char temp = clave[i];
            clave[i] = clave[j];
            clave[j] = temp;
        }
        return new String(clave);
    }

    /**
     * Obtiene la clave AES de 256 bits desde una variable de entorno ({@code COOPEVIDA_AES_KEY})
     * o desde el archivo externo {@code config.properties} (propiedad {@code aes.key}).
     * <p>
     * Cumple el requisito R6: la clave nunca se encuentra en el código fuente.
     */
    private static SecretKey obtenerClaveAES() {
        String claveB64 = System.getenv("COOPEVIDA_AES_KEY");
        if (claveB64 == null || claveB64.isBlank()) {
            Properties props = cargarPropiedadesExternas();
            claveB64 = props.getProperty("aes.key");
        }
        if (claveB64 == null || claveB64.isBlank()) {
            throw new IllegalStateException("No se encontró la clave AES en config.properties ni en COOPEVIDA_AES_KEY");
        }
        byte[] bytesClave;
        try {
            bytesClave = Base64.getDecoder().decode(claveB64.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("La clave AES configurada no está en formato Base64 válido", e);
        }
        if (bytesClave.length != LONGITUD_CLAVE_AES_BYTES) {
            throw new IllegalStateException("La clave AES debe ser exactamente de 256 bits (32 bytes)");
        }
        return new SecretKeySpec(bytesClave, "AES");
    }

    /**
     * Carga el archivo externo {@code config.properties} ubicado en el directorio de
     * ejecución o en la ruta indicada por la propiedad del sistema {@code coopevida.config}.
     */
    public static Properties cargarPropiedadesExternas() {
        String rutaArchivo = System.getProperty("coopevida.config", "config.properties");
        File archivo = new File(rutaArchivo);
        Properties props = new Properties();
        if (archivo.exists() && archivo.isFile()) {
            try (FileInputStream fis = new FileInputStream(archivo)) {
                props.load(fis);
            } catch (IOException e) {
                throw new IllegalStateException("No se pudo leer el archivo de configuración externo", e);
            }
        }
        return props;
    }
}
