package seguridad;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Toda la criptografía de la aplicación, con la API estándar de Java (javax.crypto).
 *
 * R1: las contraseñas se guardan como hash PBKDF2. Un hash no se puede revertir:
 *     para iniciar sesión se vuelve a calcular y se compara.
 * R6: el saldo y los montos se guardan cifrados con AES-GCM, que sí se puede
 *     descifrar con la clave, y además detecta si alguien modificó el dato cifrado.
 * También genera la contraseña inicial aleatoria de los usuarios nuevos.
 */
public final class Cripto {

    // R1: parámetros de PBKDF2 que pide el enunciado
    private static final String ALGORITMO_PBKDF2 = "PBKDF2WithHmacSHA256";
    public static final int ITERACIONES_PBKDF2 = 600_000; // muchas vueltas = adivinar contraseñas es muy lento
    private static final int LONGITUD_SAL_BYTES = 16;
    private static final int LONGITUD_HASH_BITS = 256;

    // R6: parámetros de AES-GCM
    private static final String ALGORITMO_AES_GCM = "AES/GCM/NoPadding";
    private static final int LONGITUD_IV_BYTES = 12;
    private static final int LONGITUD_TAG_BITS = 128;      // etiqueta de 16 bytes que detecta cambios
    private static final int LONGITUD_CLAVE_AES_BYTES = 32; // 256 bits

    // Caracteres para la contraseña inicial (sin letras que se confunden, como O/0 o l/1)
    private static final String MAYUSCULAS = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final String MINUSCULAS = "abcdefghijkmnopqrstuvwxyz";
    private static final String NUMEROS = "23456789";
    private static final String SIMBOLOS = "#$%&*+-=@!?";
    private static final String TODOS_CARACTERES = MAYUSCULAS + MINUSCULAS + NUMEROS + SIMBOLOS;
    private static final int LONGITUD_CLAVE_INICIAL = 14;

    // Generador de números aleatorios seguro para criptografía (no usar Random)
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Hash de una contraseña inventada, para usarlo cuando el usuario no existe
    private static final String HASH_FICTICIO = generarHashFicticio();

    private Cripto() {
        // Solo tiene métodos estáticos
    }

    /**
     * R1: calcula el hash PBKDF2 de una contraseña.
     * La sal son 16 bytes aleatorios distintos para cada usuario: así dos personas con la
     * misma contraseña tienen hashes diferentes y no sirven las tablas precalculadas.
     * Se guarda como texto "iteraciones:sal:hash" (sal y hash en Base64).
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
     * R1: revisa si la contraseña escrita corresponde al hash guardado.
     * Se calcula otra vez el hash con la misma sal y se comparan los resultados.
     * MessageDigest.isEqual compara siempre todos los bytes, así el tiempo de respuesta
     * no da pistas de cuántos caracteres coincidieron.
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
                return false; // no se aceptan hashes más débiles que lo que pide R1
            }
            byte[] sal = Base64.getDecoder().decode(partes[1]);
            byte[] hashEsperado = Base64.getDecoder().decode(partes[2]);

            byte[] hashCalculado = calcularPBKDF2(contrasena, sal, iteraciones, hashEsperado.length * 8);
            return MessageDigest.isEqual(hashCalculado, hashEsperado);
        } catch (IllegalArgumentException e) {
            return false; // hash guardado con formato inválido
        }
    }

    /**
     * Si el usuario no existe, igual se calcula PBKDF2 contra un hash ficticio.
     * Así la respuesta tarda lo mismo exista o no el usuario, y un atacante no puede
     * averiguar qué usuarios existen midiendo el tiempo (recomendación del enunciado).
     */
    public static void verificarContrasenaFicticia(char[] contrasena) {
        char[] entrada = (contrasena != null && contrasena.length > 0)
                ? contrasena
                : "clave_ficticia_temporal".toCharArray();
        verificarContrasena(entrada, HASH_FICTICIO);
    }

    // Cálculo de PBKDF2 con javax.crypto. Al final se borra la contraseña de memoria.
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

    // R6: cifra un monto o saldo. Se convierte a texto y se cifra con AES-GCM.
    public static byte[] cifrar(BigDecimal valor) {
        if (valor == null) {
            throw new IllegalArgumentException("El valor a cifrar no puede ser nulo.");
        }
        return cifrarTexto(valor.toPlainString());
    }

    // R6: descifra un monto o saldo guardado en la base de datos.
    public static BigDecimal descifrar(byte[] datosCifrados) {
        String texto = descifrarTexto(datosCifrados);
        try {
            return new BigDecimal(texto);
        } catch (NumberFormatException e) {
            throw new IllegalStateException("El dato descifrado no tiene un formato numérico válido", e);
        }
    }

    /**
     * R6: cifra un texto con AES-GCM y clave de 256 bits.
     * El IV son 12 bytes aleatorios nuevos en cada cifrado: así el mismo saldo cifrado
     * dos veces se ve distinto en la base de datos. El IV no es secreto, pero se necesita
     * para descifrar, por eso se guarda al inicio del resultado.
     * Resultado: IV (12 bytes) + dato cifrado + etiqueta (16 bytes).
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

            // doFinal devuelve el dato cifrado con la etiqueta ya pegada al final
            byte[] cifradoConTag = cipher.doFinal(textoEnClaro.getBytes(StandardCharsets.UTF_8));

            // Se pone el IV adelante: IV + cifrado + etiqueta
            byte[] resultado = new byte[iv.length + cifradoConTag.length];
            System.arraycopy(iv, 0, resultado, 0, iv.length);
            System.arraycopy(cifradoConTag, 0, resultado, iv.length, cifradoConTag.length);
            return resultado;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Error al cifrar datos con AES-GCM", e);
        }
    }

    /**
     * R6: descifra lo que produjo cifrarTexto. Primero separa el IV del resto.
     * Si alguien cambió aunque sea un byte en la base de datos, la etiqueta no coincide
     * y AES-GCM da error en lugar de devolver un dato alterado.
     */
    public static String descifrarTexto(byte[] datosCifrados) {
        // Como mínimo debe haber 12 (IV) + 1 (dato) + 16 (etiqueta) = 29 bytes
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
     * Genera la contraseña inicial de un usuario nuevo: 14 caracteres al azar con
     * SecureRandom, con al menos una mayúscula, una minúscula, un número y un símbolo.
     */
    public static String generarContrasenaInicial() {
        char[] clave = new char[LONGITUD_CLAVE_INICIAL];
        // Los primeros 4 aseguran que haya uno de cada tipo
        clave[0] = MAYUSCULAS.charAt(SECURE_RANDOM.nextInt(MAYUSCULAS.length()));
        clave[1] = MINUSCULAS.charAt(SECURE_RANDOM.nextInt(MINUSCULAS.length()));
        clave[2] = NUMEROS.charAt(SECURE_RANDOM.nextInt(NUMEROS.length()));
        clave[3] = SIMBOLOS.charAt(SECURE_RANDOM.nextInt(SIMBOLOS.length()));

        // El resto, de cualquier tipo
        for (int i = 4; i < LONGITUD_CLAVE_INICIAL; i++) {
            clave[i] = TODOS_CARACTERES.charAt(SECURE_RANDOM.nextInt(TODOS_CARACTERES.length()));
        }

        // Se revuelven las posiciones para que la mayúscula no quede siempre de primera
        for (int i = clave.length - 1; i > 0; i--) {
            int j = SECURE_RANDOM.nextInt(i + 1);
            char temp = clave[i];
            clave[i] = clave[j];
            clave[j] = temp;
        }
        return new String(clave);
    }

    /**
     * R6: la clave AES no está en el código. Se lee de la variable de entorno
     * COOPEVIDA_AES_KEY o de config.properties (aes.key), en Base64, y debe medir 32 bytes.
     */
    private static SecretKey obtenerClaveAES() {
        String claveB64 = Configuracion.obtener("COOPEVIDA_AES_KEY", "aes.key");
        if (claveB64 == null) {
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
}
