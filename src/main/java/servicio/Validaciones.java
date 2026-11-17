package servicio;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * R5: validación de entradas por lista blanca.
 *
 * "Lista blanca" significa que se define exactamente lo que SÍ se acepta (por ejemplo,
 * 9 dígitos) y se rechaza todo lo demás, en lugar de intentar adivinar lo malo.
 * Si un dato no cumple, se lanza IllegalArgumentException con el nombre del campo y la
 * operación se detiene antes de tocar la base de datos.
 * Solo la usa CoopevidaServicio, así que la validación sigue en la capa de servicios.
 */
public final class Validaciones {

    // Patrones (expresiones regulares): ^ y $ obligan a que TODO el texto cumpla
    private static final Pattern PATRON_USUARIO = Pattern.compile("^[a-z0-9._]{4,20}$");
    private static final Pattern PATRON_CEDULA = Pattern.compile("^[0-9]{9}$");
    private static final Pattern PATRON_REFERENCIA = Pattern.compile("^[A-Za-z0-9-]{1,20}$");

    // Monto: hasta 13 dígitos enteros y 2 decimales. El límite asegura que el monto
    // cifrado quepa en la columna de la base de datos (VARBINARY(64)).
    private static final Pattern PATRON_MONTO = Pattern.compile("^[0-9]{1,13}(\\.[0-9]{1,2})?$");

    // Largo de las contraseñas nuevas (R2)
    private static final int CLAVE_MINIMO = 12;
    private static final int CLAVE_MAXIMO = 128;

    private Validaciones() {
        // Solo tiene métodos estáticos
    }

    /** Cédula: obligatoria, exactamente 9 dígitos, sin guiones ni espacios. */
    public static String validarCedula(String cedula) {
        if (cedula == null || cedula.isEmpty()) {
            throw new IllegalArgumentException("El campo 'Cédula' es obligatorio.");
        }
        if (!PATRON_CEDULA.matcher(cedula).matches()) {
            throw new IllegalArgumentException(
                    "El campo 'Cédula' debe contener exactamente 9 dígitos numéricos, sin guiones ni espacios.");
        }
        return cedula;
    }

    /** Tipo: obligatorio, Depósito o Retiro. Devuelve el valor que se guarda en la BD. */
    public static String validarTipoMovimiento(String tipo) {
        if (tipo == null || tipo.trim().isEmpty()) {
            throw new IllegalArgumentException("El campo 'Tipo' es obligatorio.");
        }
        String t = tipo.trim().toLowerCase();
        if (t.equals("depósito") || t.equals("deposito")) {
            return "deposito";
        }
        if (t.equals("retiro")) {
            return "retiro";
        }
        throw new IllegalArgumentException("El campo 'Tipo' debe ser Depósito o Retiro.");
    }

    /** Monto: obligatorio, número mayor que 0 con máximo 2 decimales. */
    public static BigDecimal validarMonto(String montoTexto) {
        if (montoTexto == null || montoTexto.trim().isEmpty()) {
            throw new IllegalArgumentException("El campo 'Monto' es obligatorio.");
        }
        String limpio = montoTexto.trim();
        if (!PATRON_MONTO.matcher(limpio).matches()) {
            throw new IllegalArgumentException(
                    "El campo 'Monto' debe ser un número positivo de hasta 13 dígitos enteros "
                    + "y un máximo de 2 decimales.");
        }
        BigDecimal monto = new BigDecimal(limpio);
        if (monto.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("El campo 'Monto' debe ser mayor que 0.");
        }
        return monto;
    }

    /** Referencia: obligatoria, hasta 20 caracteres, solo letras, números y guion. */
    public static String validarReferencia(String referencia) {
        if (referencia == null || referencia.trim().isEmpty()) {
            throw new IllegalArgumentException("El campo 'Referencia' es obligatorio.");
        }
        String limpia = referencia.trim();
        if (!PATRON_REFERENCIA.matcher(limpia).matches()) {
            throw new IllegalArgumentException(
                    "El campo 'Referencia' debe tener hasta 20 caracteres (solo letras, números y guion).");
        }
        return limpia;
    }

    /** Nombre de usuario: obligatorio, 4 a 20 caracteres: minúsculas, números, punto y guion bajo. */
    public static String validarNombreUsuario(String nombreUsuario) {
        if (nombreUsuario == null || nombreUsuario.trim().isEmpty()) {
            throw new IllegalArgumentException("El campo 'Nombre de usuario' es obligatorio.");
        }
        String limpio = nombreUsuario.trim();
        if (!PATRON_USUARIO.matcher(limpio).matches()) {
            throw new IllegalArgumentException(
                    "El campo 'Nombre de usuario' debe tener de 4 a 20 caracteres y contener solo "
                    + "letras minúsculas, números, punto (.) o guion bajo (_).");
        }
        return limpio;
    }

    /**
     * Cambio de contraseña: los tres campos son obligatorios, la nueva debe tener de 12 a 128
     * caracteres (R2) y la confirmación debe ser igual a la nueva.
     * Que la contraseña actual sea la correcta lo revisa el servicio contra el hash guardado.
     */
    public static void validarCambioContrasena(char[] actual, char[] nueva, char[] confirmar) {
        if (actual == null || actual.length == 0) {
            throw new IllegalArgumentException("El campo 'Contraseña actual' es obligatorio.");
        }
        if (nueva == null || nueva.length == 0) {
            throw new IllegalArgumentException("El campo 'Contraseña nueva' es obligatorio.");
        }
        if (nueva.length < CLAVE_MINIMO || nueva.length > CLAVE_MAXIMO) {
            throw new IllegalArgumentException("El campo 'Contraseña nueva' debe tener entre 12 y 128 caracteres.");
        }
        if (confirmar == null || confirmar.length == 0) {
            throw new IllegalArgumentException("El campo 'Confirmar contraseña nueva' es obligatorio.");
        }
        if (!Arrays.equals(nueva, confirmar)) {
            throw new IllegalArgumentException(
                    "El campo 'Confirmar contraseña nueva' no coincide con la contraseña nueva.");
        }
    }
}
