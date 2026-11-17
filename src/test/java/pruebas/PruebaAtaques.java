package pruebas;

import modelo.Usuario;
import seguridad.AccesoDenegadoException;
import servicio.CoopevidaServicio;

/**
 * Programa de pruebas de seguridad (pentest) contra la propia aplicación.
 *
 * Las ventanas ocultan las opciones que cada rol no puede usar, así que desde la
 * interfaz no se puede "intentar" un ataque. Este programa hace lo que haría un atacante
 * que modifica el cliente: llama directamente a CoopevidaServicio, saltándose las ventanas.
 * Si los controles están bien puestos en la capa de servicios, TODOS los ataques deben
 * ser rechazados (R3 y R5) y quedar registrados en la bitácora (R8).
 *
 * Ningún ataque debería modificar datos: si uno tiene éxito, se marca como VULNERABLE.
 * Se ejecuta en NetBeans con clic derecho → Run File, con la base de datos encendida
 * y los datos de CargaInicial cargados.
 */
public class PruebaAtaques {

    // Cuentas de prueba del README (datos de CargaInicial)
    private static final String CEDULA_ASOCIADO1 = "112340567";
    private static final String CEDULA_ASOCIADO2 = "205670891";

    private static int bloqueados = 0;
    private static int vulnerables = 0;
    private static int erroresTecnicos = 0;

    public static void main(String[] args) {
        CoopevidaServicio servicio = new CoopevidaServicio();

        System.out.println("=== COOPEVIDA - Pruebas de ataque contra la capa de servicios ===\n");

        // Se inicia sesión de forma normal con cada rol (contraseñas del README)
        Usuario asociado1 = iniciar(servicio, "asociado1", "Asoc1-Coop#2026");
        Usuario ejecutivo1 = iniciar(servicio, "ejecutivo1", "Ejec1-Coop#2026");
        Usuario admin1 = iniciar(servicio, "admin1", "Admin1-Coop#2026");
        if (asociado1 == null || ejecutivo1 == null || admin1 == null) {
            System.out.println("\nNo se pudo iniciar sesión. Revise que MariaDB esté encendida,"
                    + " que exista config.properties y que se haya ejecutado CargaInicial.");
            return;
        }

        System.out.println("\n--- 1. Ver la cuenta de otro asociado cambiando la cédula (R3, pertenencia) ---");
        intentar("asociado1 pide la cuenta de asociado2 (" + CEDULA_ASOCIADO2 + ")",
                () -> servicio.consultarCuenta(asociado1, CEDULA_ASOCIADO2));
        intentar("asociado1 pide una cédula que no existe (999999999)",
                () -> servicio.consultarCuenta(asociado1, "999999999"));

        System.out.println("\n--- 2. Operaciones de otro rol (R3, permisos) ---");
        intentar("asociado1 registra un depósito en su propia cuenta",
                () -> servicio.registrarMovimiento(asociado1, CEDULA_ASOCIADO1, "Depósito", "1000000", "HACK-01"));
        intentar("asociado1 lista los usuarios del sistema",
                () -> servicio.listarUsuarios(asociado1));
        intentar("asociado1 se crea un usuario administrador",
                () -> servicio.crearUsuario(asociado1, "hacker1", "Administrador", null));
        intentar("ejecutivo1 crea un usuario administrador",
                () -> servicio.crearUsuario(ejecutivo1, "hacker2", "Administrador", null));
        intentar("ejecutivo1 lista asociados sin usuario (solo Administrador)",
                () -> servicio.listarAsociadosSinUsuario(ejecutivo1));
        intentar("admin1 consulta la cuenta de un asociado (el Administrador no ve cuentas)",
                () -> servicio.consultarCuenta(admin1, CEDULA_ASOCIADO1));
        intentar("admin1 registra un retiro",
                () -> servicio.registrarMovimiento(admin1, CEDULA_ASOCIADO1, "Retiro", "1000", "HACK-02"));
        intentar("operación sin sesión (usuario nulo)",
                () -> servicio.listarUsuarios(null));

        System.out.println("\n--- 3. Manipulación de valores como ejecutivo1 (R5 y reglas del negocio) ---");
        intentar("depósito con monto negativo (-5000)",
                () -> servicio.registrarMovimiento(ejecutivo1, CEDULA_ASOCIADO1, "Depósito", "-5000", "HACK-03"));
        intentar("depósito con monto cero (0)",
                () -> servicio.registrarMovimiento(ejecutivo1, CEDULA_ASOCIADO1, "Depósito", "0", "HACK-04"));
        intentar("retiro mayor que el saldo (999999999)",
                () -> servicio.registrarMovimiento(ejecutivo1, CEDULA_ASOCIADO1, "Retiro", "999999999", "HACK-05"));
        intentar("monto con 3 decimales (10.555)",
                () -> servicio.registrarMovimiento(ejecutivo1, CEDULA_ASOCIADO1, "Depósito", "10.555", "HACK-06"));
        intentar("monto gigante de 40 dígitos",
                () -> servicio.registrarMovimiento(ejecutivo1, CEDULA_ASOCIADO1, "Depósito",
                        "1234567890123456789012345678901234567890", "HACK-07"));
        intentar("tipo de movimiento inventado (Transferencia)",
                () -> servicio.registrarMovimiento(ejecutivo1, CEDULA_ASOCIADO1, "Transferencia", "100", "HACK-08"));

        System.out.println("\n--- 4. Inyección SQL en campos distintos al login (R4 y R5) ---");
        intentar("cédula con inyección: 112340567' OR '1'='1",
                () -> servicio.consultarCuenta(ejecutivo1, "112340567' OR '1'='1"));
        intentar("referencia con inyección: X'; DROP TABLE cuenta; --",
                () -> servicio.registrarMovimiento(ejecutivo1, CEDULA_ASOCIADO1, "Depósito", "100",
                        "X'; DROP TABLE cuenta; --"));
        intentar("nombre de usuario con inyección: a' OR '1'='1",
                () -> servicio.crearUsuario(admin1, "a' OR '1'='1", "Ejecutivo", null));

        System.out.println("\n=== Resumen ===");
        System.out.println("Ataques bloqueados : " + bloqueados);
        System.out.println("VULNERABLES        : " + vulnerables);
        System.out.println("Errores técnicos   : " + erroresTecnicos);
        System.out.println("\nRevise la bitácora con root para ver los ACCESO_DENEGADO registrados:");
        System.out.println("  SELECT fecha_hora, usuario_nombre, evento, detalle, resultado");
        System.out.println("  FROM coopevida.bitacora ORDER BY id DESC LIMIT 30;");
    }

    // Inicia sesión normalmente. Devuelve null si no se pudo.
    private static Usuario iniciar(CoopevidaServicio servicio, String usuario, String clave) {
        try {
            Usuario u = servicio.iniciarSesion(usuario, clave.toCharArray());
            System.out.println("Sesión iniciada: " + usuario + " (" + u.getRol().getNombre() + ")");
            return u;
        } catch (RuntimeException e) {
            System.out.println("No se pudo iniciar sesión con " + usuario + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Ejecuta un ataque y muestra el resultado.
     *   - Si el servicio lo rechaza (acceso denegado o dato inválido): BLOQUEADO.
     *   - Si la operación se completa: VULNERABLE (el control falló).
     *   - Si sale el mensaje M02: error técnico (no es un ataque exitoso, pero hay que revisarlo).
     */
    private static void intentar(String descripcion, Runnable ataque) {
        System.out.print("  " + descripcion + "\n      -> ");
        try {
            ataque.run();
            vulnerables++;
            System.out.println("VULNERABLE: la operación se ejecutó");
        } catch (AccesoDenegadoException e) {
            bloqueados++;
            System.out.println("BLOQUEADO (permiso): " + e.getMessage());
        } catch (IllegalArgumentException e) {
            bloqueados++;
            System.out.println("BLOQUEADO (validación): " + e.getMessage());
        } catch (IllegalStateException e) {
            erroresTecnicos++;
            System.out.println("ERROR TÉCNICO: " + e.getMessage());
        }
    }
}
