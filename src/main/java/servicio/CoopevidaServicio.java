package servicio;

import dao.CoopevidaDAO;
import dao.CoopevidaDAO.RegistroAutenticacion;
import java.math.BigDecimal;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import modelo.Asociado;
import modelo.Cuenta;
import modelo.Movimiento;
import modelo.Usuario;
import modelo.Usuario.Rol;
import seguridad.AccesoDenegadoException;
import seguridad.ControlAcceso;
import seguridad.ControlAcceso.Permiso;
import seguridad.Cripto;

/**
 * Capa de servicios del sistema COOPEVIDA.
 * <p>
 * Centraliza todos los controles de seguridad de la aplicación en el orden exigido:
 * <ol>
 *   <li>Verificación del permiso del rol y pertenencia de los datos (R3).</li>
 *   <li>Validación de entradas por lista blanca (R5).</li>
 *   <li>Aplicación de reglas del negocio (retiro no mayor al saldo, unicidad, etc.).</li>
 *   <li>Cifrado y descifrado de datos sensibles con AES-GCM (R6).</li>
 *   <li>Ejecución transaccional de modificaciones por medio del DAO.</li>
 *   <li>Registro de auditoría en la bitácora de solo inserción (R8).</li>
 *   <li>Conversión de fallos técnicos en el mensaje genérico M02 con código de referencia (R9).</li>
 * </ol>
 */
public class CoopevidaServicio {

    // Mensajes de seguridad fijos exigidos por el enunciado
    public static final String MENSAJE_M01 = "Usuario o contraseña incorrectos.";
    private static final String PLANTILLA_M02 =
            "No fue posible completar la operación. Intente de nuevo; si el problema continúa, "
            + "comuníquese con el administrador. (Ref. %s)";

    // Parámetros de política de bloqueo de inicio de sesión (R2)
    public static final int MAX_INTENTOS_FALLIDOS = 5;
    public static final long DURACION_BLOQUEO_MS = 15_000L; // 15 segundos

    // Expresiones regulares de validación por lista blanca (R5)
    private static final Pattern PATRON_USUARIO = Pattern.compile("^[a-z0-9._]{4,20}$");
    private static final Pattern PATRON_CEDULA = Pattern.compile("^[0-9]{9}$");
    private static final Pattern PATRON_MONTO = Pattern.compile("^[0-9]+(\\.[0-9]{1,2})?$");
    private static final Pattern PATRON_REFERENCIA = Pattern.compile("^[A-Za-z0-9-]{1,20}$");

    // Eventos oficiales de la bitácora (R8)
    public static final String EVENTO_LOGIN_EXITOSO = "LOGIN_EXITOSO";
    public static final String EVENTO_LOGIN_FALLIDO = "LOGIN_FALLIDO";
    public static final String EVENTO_BLOQUEO_INICIO = "BLOQUEO_INICIO";
    public static final String EVENTO_ACCESO_DENEGADO = "ACCESO_DENEGADO";
    public static final String EVENTO_USUARIO_CREADO = "USUARIO_CREADO";
    public static final String EVENTO_MOVIMIENTO_REGISTRADO = "MOVIMIENTO_REGISTRADO";
    public static final String EVENTO_ERROR_SISTEMA = "ERROR_SISTEMA";

    // Resultados posibles en la tabla bitacora
    public static final String RESULTADO_EXITO = "Exito";
    public static final String RESULTADO_FALLIDO = "Fallido";
    public static final String RESULTADO_DENEGADO = "Denegado";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final CoopevidaDAO dao;

    // Estado en memoria para intentos fallidos consecutivos de inicio de sesión (R2)
    private int intentosFallidosConsecutivos = 0;
    private long bloqueadoHastaEpochMs = 0L;

    public CoopevidaServicio() {
        this.dao = new CoopevidaDAO();
    }

    public CoopevidaServicio(CoopevidaDAO dao) {
        this.dao = dao;
    }

    /**
     * Indica si el inicio de sesión se encuentra temporalmente bloqueado (15 s).
     */
    public synchronized boolean estaInicioBloqueado() {
        return System.currentTimeMillis() < bloqueadoHastaEpochMs;
    }

    /**
     * Devuelve los segundos restantes del bloqueo de inicio de sesión, o 0 si no está bloqueado.
     */
    public synchronized int obtenerSegundosRestantesBloqueo() {
        long restanteMs = bloqueadoHastaEpochMs - System.currentTimeMillis();
        if (restanteMs <= 0) {
            return 0;
        }
        return (int) Math.ceil(restanteMs / 1000.0);
    }

    /**
     * Devuelve la cantidad actual de intentos fallidos consecutivos en memoria.
     */
    public synchronized int getIntentosFallidosConsecutivos() {
        return intentosFallidosConsecutivos;
    }

    /**
     * Operación de inicio de sesión (R1, R2, R8, R9).
     * <ol>
     *   <li>Si usuario o contraseña están vacíos, lo indica y no consulta la BD.</li>
     *   <li>Busca el usuario con consulta parametrizada y verifica con PBKDF2.</li>
     *   <li>Si no existe, verifica contra un hash ficticio para evitar enumeración por tiempo.</li>
     *   <li>Si falla, incrementa contador en memoria, registra {@code LOGIN_FALLIDO} y, al llegar
     *       a 5 intentos consecutivos, bloquea por 15 segundos, registra {@code BLOQUEO_INICIO}
     *       y reinicia el contador a 0.</li>
     *   <li>Si tiene éxito, reinicia el contador a 0, registra {@code LOGIN_EXITOSO} y devuelve el {@link Usuario}.</li>
     * </ol>
     */
    public synchronized Usuario iniciarSesion(String nombreUsuario, char[] contrasena) {
        try {
            if (estaInicioBloqueado()) {
                throw new IllegalArgumentException(
                        "El inicio de sesión está bloqueado temporalmente. Espere "
                        + obtenerSegundosRestantesBloqueo() + " segundos.");
            }

            if (nombreUsuario == null || nombreUsuario.trim().isEmpty()) {
                throw new IllegalArgumentException("El campo 'Usuario' es obligatorio.");
            }
            if (contrasena == null || contrasena.length == 0) {
                throw new IllegalArgumentException("El campo 'Contraseña' es obligatorio.");
            }

            String usuarioLimpio = nombreUsuario.trim();

            try {
                RegistroAutenticacion reg = dao.buscarUsuarioPorNombre(usuarioLimpio);
                boolean autenticado;
                if (reg == null) {
                    // Usuario inexistente: ejecutar PBKDF2 contra hash ficticio (mitigación de timing attack)
                    Cripto.verificarContrasenaFicticia(contrasena);
                    autenticado = false;
                } else {
                    autenticado = Cripto.verificarContrasena(contrasena, reg.getHashContrasena());
                }

                if (!autenticado) {
                    intentosFallidosConsecutivos++;
                    registrarBitacoraSeguro(usuarioLimpio, EVENTO_LOGIN_FALLIDO,
                            "Intento fallido #" + intentosFallidosConsecutivos, RESULTADO_FALLIDO);

                    if (intentosFallidosConsecutivos >= MAX_INTENTOS_FALLIDOS) {
                        bloqueadoHastaEpochMs = System.currentTimeMillis() + DURACION_BLOQUEO_MS;
                        intentosFallidosConsecutivos = 0;
                        registrarBitacoraSeguro(usuarioLimpio, EVENTO_BLOQUEO_INICIO,
                                "5 intentos fallidos consecutivos alcanzados (bloqueo 15s)", RESULTADO_FALLIDO);
                    }
                    throw new IllegalArgumentException(MENSAJE_M01);
                }

                // Éxito: reiniciar contador y registrar en bitácora
                intentosFallidosConsecutivos = 0;
                bloqueadoHastaEpochMs = 0L;
                Usuario usuarioAutenticado = reg.getUsuario();
                registrarBitacoraSeguro(usuarioAutenticado.getNombreUsuario(),
                        EVENTO_LOGIN_EXITOSO, "Rol: " + usuarioAutenticado.getRol().getNombre(), RESULTADO_EXITO);
                return usuarioAutenticado;

            } catch (SQLException e) {
                throw manejarErrorTecnico(usuarioLimpio, e);
            }
        } finally {
            if (contrasena != null) {
                Arrays.fill(contrasena, '\0');
            }
        }
    }

    /**
     * Sesión → Cambiar mi contraseña (todos los roles, permiso {@code SESION_CAMBIAR_CLAVE}).
     * Verifica la contraseña actual, exige entre 12 y 128 caracteres para la nueva,
     * comprueba la confirmación y guarda un nuevo hash PBKDF2 con sal nueva.
     */
    public void cambiarContrasena(Usuario sesion, char[] contrasenaActual,
                                  char[] contrasenaNueva, char[] confirmarContrasenaNueva) {
        try {
            // 1. Verificar permiso del rol (R3)
            verificarPermisoConBitacora(sesion, Permiso.SESION_CAMBIAR_CLAVE, "Cambiar contraseña");

            // 2. Validar entradas por lista blanca (R5)
            if (contrasenaActual == null || contrasenaActual.length == 0) {
                throw new IllegalArgumentException("El campo 'Contraseña actual' es obligatorio.");
            }
            if (contrasenaNueva == null || contrasenaNueva.length == 0) {
                throw new IllegalArgumentException("El campo 'Contraseña nueva' es obligatorio.");
            }
            if (contrasenaNueva.length < 12 || contrasenaNueva.length > 128) {
                throw new IllegalArgumentException("El campo 'Contraseña nueva' debe tener entre 12 y 128 caracteres.");
            }
            if (confirmarContrasenaNueva == null || confirmarContrasenaNueva.length == 0) {
                throw new IllegalArgumentException("El campo 'Confirmar contraseña nueva' es obligatorio.");
            }
            if (!Arrays.equals(contrasenaNueva, confirmarContrasenaNueva)) {
                throw new IllegalArgumentException("El campo 'Confirmar contraseña nueva' no coincide con la contraseña nueva.");
            }

            // 3. Verificar que la contraseña actual coincida con la almacenada y guardar nuevo hash
            try {
                String hashActual = dao.obtenerHashPorId(sesion.getId());
                if (hashActual == null || !Cripto.verificarContrasena(contrasenaActual, hashActual)) {
                    throw new IllegalArgumentException("El campo 'Contraseña actual' no coincide con la contraseña del usuario.");
                }

                String nuevoHash = Cripto.hashContrasena(contrasenaNueva);
                dao.actualizarHashContrasena(sesion.getId(), nuevoHash);
            } catch (SQLException e) {
                throw manejarErrorTecnico(sesion.getNombreUsuario(), e);
            }
        } finally {
            if (contrasenaActual != null) {
                Arrays.fill(contrasenaActual, '\0');
            }
            if (contrasenaNueva != null) {
                Arrays.fill(contrasenaNueva, '\0');
            }
            if (confirmarContrasenaNueva != null) {
                Arrays.fill(confirmarContrasenaNueva, '\0');
            }
        }
    }

    /**
     * Obtiene el resumen de una cuenta (nombre del asociado y saldo actual descifrado)
     * para que el Ejecutivo verifique los datos antes de registrar un movimiento.
     */
    public Cuenta obtenerResumenCuentaParaMovimiento(Usuario sesion, String cedula) {
        // 1. Verificar permiso MOVIMIENTO_REGISTRAR (R3)
        verificarPermisoConBitacora(sesion, Permiso.MOVIMIENTO_REGISTRAR,
                "Resumen cuenta para movimiento: cedula=" + valorSeguro(cedula));

        // 2. Validar cédula por lista blanca (R5)
        String cedulaLimpia = validarCedula(cedula);

        // 3. Consultar cuenta y descifrar saldo (R6)
        try {
            Cuenta cuenta = dao.buscarCuentaPorCedula(cedulaLimpia);
            if (cuenta == null) {
                throw new IllegalArgumentException("No existe ningún asociado con la cédula indicada.");
            }
            BigDecimal saldoActual = Cripto.descifrar(cuenta.getSaldoCifrado());
            cuenta.setSaldo(saldoActual);
            return cuenta;
        } catch (SQLException | IllegalStateException e) {
            throw manejarErrorTecnico(sesion.getNombreUsuario(), e);
        }
    }

    /**
     * Cuentas → Registrar movimiento (Ejecutivo, permiso {@code MOVIMIENTO_REGISTRAR}).
     * <p>
     * Valida los campos por lista blanca, verifica que un retiro no supere el saldo actual,
     * cifra el monto y el nuevo saldo con AES-GCM, ejecuta la inserción y actualización
     * en una sola transacción y registra {@code MOVIMIENTO_REGISTRADO} en la bitácora
     * (sin incluir monto ni saldo).
     *
     * @return El nuevo saldo de la cuenta después de aplicar el movimiento.
     */
    public BigDecimal registrarMovimiento(Usuario sesion, String cedula, String tipo,
                                          String montoTexto, String referencia) {
        // 1. Verificar permiso del rol (R3)
        verificarPermisoConBitacora(sesion, Permiso.MOVIMIENTO_REGISTRAR,
                "Registrar movimiento: cedula=" + valorSeguro(cedula));

        // 2. Validar entradas por lista blanca (R5)
        String cedulaLimpia = validarCedula(cedula);
        String tipoNormalizado = validarTipoMovimiento(tipo);
        BigDecimal monto = validarMonto(montoTexto);
        String referenciaLimpia = validarReferencia(referencia);

        // 3. Aplicar reglas del negocio, cifrar con AES-GCM (R6), ejecutar transacción y registrar en bitácora (R8)
        try {
            Cuenta cuenta = dao.buscarCuentaPorCedula(cedulaLimpia);
            if (cuenta == null) {
                throw new IllegalArgumentException("No existe ningún asociado con la cédula indicada.");
            }

            BigDecimal saldoActual = Cripto.descifrar(cuenta.getSaldoCifrado());
            BigDecimal nuevoSaldo;

            if ("retiro".equals(tipoNormalizado)) {
                if (monto.compareTo(saldoActual) > 0) {
                    throw new IllegalArgumentException(
                            "El campo 'Monto' no puede superar el saldo actual de la cuenta (₡"
                            + saldoActual.toPlainString() + ").");
                }
                nuevoSaldo = saldoActual.subtract(monto);
            } else {
                nuevoSaldo = saldoActual.add(monto);
            }

            // Cifrar monto y nuevo saldo con AES-GCM (cada uno con IV aleatorio único de 12 bytes)
            byte[] montoCifrado = Cripto.cifrar(monto);
            byte[] nuevoSaldoCifrado = Cripto.cifrar(nuevoSaldo);

            // Ejecutar en una sola transacción atómica
            dao.registrarMovimientoYActualizarSaldo(
                    cuenta.getId(),
                    tipoNormalizado,
                    montoCifrado,
                    referenciaLimpia,
                    sesion.getId(),
                    nuevoSaldoCifrado
            );

            // Registrar en bitácora SIN monto ni saldo (R8)
            String detalleBitacora = "cedula=" + cedulaLimpia
                    + ", tipo=" + tipoNormalizado
                    + ", referencia=" + referenciaLimpia;
            registrarBitacoraSeguro(sesion.getNombreUsuario(),
                    EVENTO_MOVIMIENTO_REGISTRADO, detalleBitacora, RESULTADO_EXITO);

            return nuevoSaldo;
        } catch (SQLException | IllegalStateException e) {
            throw manejarErrorTecnico(sesion.getNombreUsuario(), e);
        }
    }

    /**
     * Cuentas → Consultar cuenta / Mi cuenta.
     * <ul>
     *   <li><b>Ejecutivo ({@code CUENTA_VER}):</b> indica la cédula de cualquier asociado (9 dígitos).</li>
     *   <li><b>Asociado ({@code CUENTA_VER_PROPIA}):</b> consulta únicamente su propia cuenta vinculada.
     *       Si se intenta especificar una cédula distinta a la del asociado de la sesión (ataque IDOR),
     *       se rechaza con mensaje de acceso denegado sin revelar si el asociado existe y se registra
     *       {@code ACCESO_DENEGADO} en la bitácora.</li>
     * </ul>
     */
    public Cuenta consultarCuenta(Usuario sesion, String cedulaSolicitada) {
        if (sesion == null || sesion.getRol() == null) {
            registrarBitacoraSeguro("(desconocido)", EVENTO_ACCESO_DENEGADO,
                    "Sesión nula al consultar cuenta", RESULTADO_DENEGADO);
            throw new AccesoDenegadoException("Acceso denegado: sesión inválida.");
        }

        if (sesion.getRol() == Rol.EJECUTIVO) {
            // 1. Verificar permiso CUENTA_VER (R3)
            verificarPermisoConBitacora(sesion, Permiso.CUENTA_VER,
                    "Consultar cuenta: cedula=" + valorSeguro(cedulaSolicitada));

            // 2. Validar cédula por lista blanca (R5)
            String cedulaLimpia = validarCedula(cedulaSolicitada);

            // 3. Consultar y descifrar saldo y movimientos (R6)
            try {
                Cuenta cuenta = dao.buscarCuentaPorCedula(cedulaLimpia);
                if (cuenta == null) {
                    throw new IllegalArgumentException("No se encontró ninguna cuenta para la cédula indicada.");
                }
                descifrarCuentaYMovimientos(cuenta);
                return cuenta;
            } catch (SQLException | IllegalStateException e) {
                throw manejarErrorTecnico(sesion.getNombreUsuario(), e);
            }

        } else if (sesion.getRol() == Rol.ASOCIADO) {
            // 1. Verificar permiso CUENTA_VER_PROPIA (R3)
            verificarPermisoConBitacora(sesion, Permiso.CUENTA_VER_PROPIA, "Consultar mi cuenta");

            if (sesion.getAsociadoId() == null) {
                registrarBitacoraSeguro(sesion.getNombreUsuario(), EVENTO_ACCESO_DENEGADO,
                        "Usuario asociado sin asociado_id vinculado", RESULTADO_DENEGADO);
                throw new AccesoDenegadoException("Acceso denegado: no tiene una cuenta vinculada.");
            }

            try {
                Cuenta cuentaPropia = dao.buscarCuentaPorAsociadoId(sesion.getAsociadoId());
                if (cuentaPropia == null) {
                    throw new AccesoDenegadoException("Acceso denegado: no fue posible acceder a la cuenta.");
                }

                // Verificación estricta de pertenencia (prevención de IDOR - R3):
                // Si la solicitud incluye una cédula y no coincide con la cédula propia del asociado de la sesión,
                // o si el asociado_id de la cuenta no coincide con el de la sesión, se rechaza y audita.
                if (cuentaPropia.getAsociadoId() != sesion.getAsociadoId()
                        || (cedulaSolicitada != null && !cedulaSolicitada.isBlank()
                            && !cedulaSolicitada.trim().equals(cuentaPropia.getCedulaAsociado()))) {
                    registrarBitacoraSeguro(sesion.getNombreUsuario(), EVENTO_ACCESO_DENEGADO,
                            "Intento de consultar cuenta ajena: cedula=" + valorSeguro(cedulaSolicitada),
                            RESULTADO_DENEGADO);
                    throw new AccesoDenegadoException("Acceso denegado: solo puede consultar su propia cuenta.");
                }

                descifrarCuentaYMovimientos(cuentaPropia);
                return cuentaPropia;
            } catch (SQLException | IllegalStateException e) {
                throw manejarErrorTecnico(sesion.getNombreUsuario(), e);
            }

        } else {
            // Cualquier otro rol (por ejemplo, Administrador intentando ver cuentas)
            registrarBitacoraSeguro(sesion.getNombreUsuario(), EVENTO_ACCESO_DENEGADO,
                    "Operación CUENTA_VER no permitida para rol " + sesion.getRol().getNombre()
                    + " (dato=" + valorSeguro(cedulaSolicitada) + ")",
                    RESULTADO_DENEGADO);
            throw new AccesoDenegadoException("Acceso denegado: su rol no tiene permiso para consultar cuentas.");
        }
    }

    /**
     * Método de conveniencia para la opción "Mi cuenta" del rol Asociado.
     */
    public Cuenta consultarMiCuenta(Usuario sesion) {
        return consultarCuenta(sesion, null);
    }

    private void descifrarCuentaYMovimientos(Cuenta cuenta) throws SQLException {
        cuenta.setSaldo(Cripto.descifrar(cuenta.getSaldoCifrado()));
        List<Movimiento> movimientos = dao.listarMovimientosPorCuenta(cuenta.getId());
        for (Movimiento m : movimientos) {
            m.setMonto(Cripto.descifrar(m.getMontoCifrado()));
        }
        cuenta.setMovimientos(movimientos);
    }

    /**
     * Administración → Usuarios: Lista todos los usuarios registrados.
     * Requiere el permiso {@code USUARIO_VER} (solo Administrador).
     */
    public List<Usuario> listarUsuarios(Usuario sesion) {
        verificarPermisoConBitacora(sesion, Permiso.USUARIO_VER, "Listar usuarios");
        try {
            return dao.listarUsuarios();
        } catch (SQLException e) {
            throw manejarErrorTecnico(sesion.getNombreUsuario(), e);
        }
    }

    /**
     * Administración → Usuarios: Lista cédula y nombre de asociados que aún no tienen usuario.
     * Requiere el permiso {@code ASOCIADO_VINCULAR} (solo Administrador).
     */
    public List<Asociado> listarAsociadosSinUsuario(Usuario sesion) {
        verificarPermisoConBitacora(sesion, Permiso.ASOCIADO_VINCULAR, "Listar asociados sin usuario");
        try {
            return dao.listarAsociadosSinUsuario();
        } catch (SQLException e) {
            throw manejarErrorTecnico(sesion.getNombreUsuario(), e);
        }
    }

    /**
     * Administración → Usuarios: Crea un nuevo usuario y genera su contraseña inicial aleatoria
     * de 14 caracteres con {@link SecureRandom}.
     * <p>
     * Requiere el permiso {@code USUARIO_CREAR} (y {@code ASOCIADO_VINCULAR} si el rol es Asociado).
     * Registra {@code USUARIO_CREADO} en la bitácora (nunca la contraseña).
     *
     * @return La contraseña inicial generada en claro para mostrarla una única vez al administrador.
     */
    public String crearUsuario(Usuario sesion, String nombreUsuario, String rolNombre, Integer asociadoId) {
        // 1. Verificar permiso USUARIO_CREAR (R3)
        verificarPermisoConBitacora(sesion, Permiso.USUARIO_CREAR,
                "Crear usuario: " + valorSeguro(nombreUsuario));

        // 2. Validar entradas por lista blanca (R5)
        if (nombreUsuario == null || nombreUsuario.trim().isEmpty()) {
            throw new IllegalArgumentException("El campo 'Nombre de usuario' es obligatorio.");
        }
        String usuarioLimpio = nombreUsuario.trim();
        if (!PATRON_USUARIO.matcher(usuarioLimpio).matches()) {
            throw new IllegalArgumentException(
                    "El campo 'Nombre de usuario' debe tener de 4 a 20 caracteres y contener solo "
                    + "letras minúsculas, números, punto (.) o guion bajo (_).");
        }

        Rol rolNuevo = Rol.desdeNombre(rolNombre);

        if (rolNuevo == Rol.ASOCIADO) {
            verificarPermisoConBitacora(sesion, Permiso.ASOCIADO_VINCULAR,
                    "Vincular asociado id=" + asociadoId);
            if (asociadoId == null || asociadoId <= 0) {
                throw new IllegalArgumentException(
                        "El campo 'Asociado vinculado' es obligatorio cuando el rol es Asociado.");
            }
        } else {
            if (asociadoId != null) {
                throw new IllegalArgumentException(
                        "El campo 'Asociado vinculado' solo aplica cuando el rol es Asociado.");
            }
        }

        // 3. Reglas del negocio, hash PBKDF2 (R1), inserción y bitácora (R8)
        try {
            if (dao.existeNombreUsuario(usuarioLimpio)) {
                throw new IllegalArgumentException("El 'Nombre de usuario' indicado ya existe.");
            }
            if (rolNuevo == Rol.ASOCIADO && !dao.asociadoDisponibleParaVincular(asociadoId)) {
                throw new IllegalArgumentException("El 'Asociado vinculado' no existe o ya tiene un usuario asignado.");
            }

            String contrasenaInicial = Cripto.generarContrasenaInicial();
            char[] charsClave = contrasenaInicial.toCharArray();
            String hash;
            try {
                hash = Cripto.hashContrasena(charsClave);
            } finally {
                Arrays.fill(charsClave, '\0');
            }

            dao.insertarUsuario(usuarioLimpio, hash, rolNuevo.getId(), asociadoId);

            registrarBitacoraSeguro(sesion.getNombreUsuario(), EVENTO_USUARIO_CREADO,
                    "usuario=" + usuarioLimpio + ", rol=" + rolNuevo.getNombre(), RESULTADO_EXITO);

            return contrasenaInicial;
        } catch (SQLException e) {
            throw manejarErrorTecnico(sesion.getNombreUsuario(), e);
        }
    }

    /**
     * Verifica el permiso en {@link ControlAcceso}; si es rechazado, registra
     * {@code ACCESO_DENEGADO} en la bitácora y propaga {@link AccesoDenegadoException}.
     */
    private void verificarPermisoConBitacora(Usuario sesion, Permiso permiso, String detalleAccion) {
        try {
            ControlAcceso.verificarPermiso(sesion, permiso);
        } catch (AccesoDenegadoException e) {
            String nombre = (sesion != null && sesion.getNombreUsuario() != null)
                    ? sesion.getNombreUsuario()
                    : "(desconocido)";
            registrarBitacoraSeguro(nombre, EVENTO_ACCESO_DENEGADO,
                    "Permiso requerido: " + permiso.name() + " (" + detalleAccion + ")",
                    RESULTADO_DENEGADO);
            throw e;
        }
    }

    private String validarCedula(String cedula) {
        if (cedula == null || cedula.isEmpty()) {
            throw new IllegalArgumentException("El campo 'Cédula' es obligatorio.");
        }
        if (!PATRON_CEDULA.matcher(cedula).matches()) {
            throw new IllegalArgumentException(
                    "El campo 'Cédula' debe contener exactamente 9 dígitos numéricos, sin guiones ni espacios.");
        }
        return cedula;
    }

    private String validarTipoMovimiento(String tipo) {
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

    private BigDecimal validarMonto(String montoTexto) {
        if (montoTexto == null || montoTexto.trim().isEmpty()) {
            throw new IllegalArgumentException("El campo 'Monto' es obligatorio.");
        }
        String limpio = montoTexto.trim();
        if (!PATRON_MONTO.matcher(limpio).matches()) {
            throw new IllegalArgumentException(
                    "El campo 'Monto' debe ser un número positivo con un máximo de 2 decimales.");
        }
        BigDecimal monto = new BigDecimal(limpio);
        if (monto.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("El campo 'Monto' debe ser mayor que 0.");
        }
        return monto;
    }

    private String validarReferencia(String referencia) {
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

    /**
     * Manejo seguro de errores técnicos (R9):
     * <ul>
     *   <li>Genera un código de referencia hexadecimal de 4 caracteres (ej. {@code A3F9}).</li>
     *   <li>Imprime la traza técnica completa únicamente en {@code System.err}.</li>
     *   <li>Registra {@code ERROR_SISTEMA} en la bitácora con el código y el tipo de excepción
     *       (sin mensaje ni traza).</li>
     *   <li>Devuelve {@link IllegalStateException} con el mensaje fijo M02.</li>
     * </ul>
     */
    private IllegalStateException manejarErrorTecnico(String usuarioNombre, Exception error) {
        String codigoRef = String.format("%04X", SECURE_RANDOM.nextInt(0x10000));
        String tipoError = error.getClass().getSimpleName();

        System.err.println("[ERROR_SISTEMA Ref. " + codigoRef + "] Usuario: "
                + (usuarioNombre != null ? usuarioNombre : "(desconocido)")
                + " | Tipo: " + tipoError);
        error.printStackTrace(System.err);

        registrarBitacoraSeguro(
                usuarioNombre != null ? usuarioNombre : "(desconocido)",
                EVENTO_ERROR_SISTEMA,
                "Ref. " + codigoRef + " · " + tipoError,
                RESULTADO_FALLIDO
        );

        return new IllegalStateException(String.format(PLANTILLA_M02, codigoRef));
    }

    private void registrarBitacoraSeguro(String usuarioNombre, String evento, String detalle, String resultado) {
        try {
            String detalleCorto = (detalle != null && detalle.length() > 250)
                    ? detalle.substring(0, 250)
                    : detalle;
            dao.insertarBitacora(usuarioNombre, evento, detalleCorto, resultado);
        } catch (SQLException ex) {
            System.err.println("[ADVERTENCIA BITÁCORA] No fue posible escribir en la bitácora: "
                    + ex.getClass().getSimpleName());
            ex.printStackTrace(System.err);
        }
    }

    private String valorSeguro(String valor) {
        if (valor == null) {
            return "(nulo)";
        }
        String limpio = valor.replaceAll("[\\r\\n]", " ").trim();
        return limpio.length() > 40 ? limpio.substring(0, 40) + "..." : limpio;
    }
}
