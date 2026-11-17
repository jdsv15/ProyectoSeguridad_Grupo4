package servicio;

import dao.CoopevidaDAO;
import dao.CoopevidaDAO.RegistroAutenticacion;
import java.math.BigDecimal;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
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
 * Capa de servicios: aquí están todas las operaciones de la aplicación y sus controles
 * de seguridad. La interfaz nunca habla con la base de datos; siempre pasa por aquí.
 *
 * Cada operación sigue el orden del enunciado:
 *   1. Revisar el permiso del rol y que los datos sean del usuario (R3).
 *   2. Validar las entradas por lista blanca (R5).
 *   3. Aplicar las reglas del negocio (por ejemplo, un retiro no puede superar el saldo).
 *   4. Cifrar o descifrar saldos y montos (R6).
 *   5. Guardar los cambios en una transacción (todo o nada).
 *   6. Registrar el evento en la bitácora (R8).
 *   7. Si algo falla por un error técnico, mostrar solo el mensaje M02 (R9).
 */
public class CoopevidaServicio {

    // Mensajes fijos del enunciado. M01 es igual exista o no el usuario (R2),
    // así un atacante no puede saber qué nombres de usuario son válidos.
    public static final String MENSAJE_M01 = "Usuario o contraseña incorrectos.";
    private static final String PLANTILLA_M02 =
            "No fue posible completar la operación. Intente de nuevo; si el problema continúa, "
            + "comuníquese con el administrador. (Ref. %s)";

    // R2: después de 5 intentos fallidos seguidos, el inicio de sesión se bloquea 15 segundos.
    // Esto frena a quien intenta adivinar contraseñas probando muchas (fuerza bruta).
    public static final int MAX_INTENTOS_FALLIDOS = 5;
    public static final long DURACION_BLOQUEO_MS = 15_000L; // 15 segundos

    // Las reglas de cada campo (R5) están en la clase Validaciones.

    // Largo máximo del saldo en texto para que, ya cifrado, quepa en la columna (64 bytes):
    // 12 del IV + 36 del saldo + 16 de la etiqueta = 64.
    private static final int LONGITUD_MAXIMA_SALDO = 36;

    // Tamaño de las columnas de la bitácora en la base de datos
    private static final int LONGITUD_MAXIMA_USUARIO_BITACORA = 50;
    private static final int LONGITUD_MAXIMA_DETALLE_BITACORA = 255;

    // R8: nombres de los eventos de la bitácora, tal como los pide el enunciado
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

    // Para generar los códigos de referencia del mensaje M02
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final CoopevidaDAO dao;

    // R2: el contador de intentos fallidos vive solo en memoria (no en la base de datos)
    // y no depende del usuario escrito, como pide el enunciado.
    private int intentosFallidosConsecutivos = 0;
    private long bloqueadoHastaEpochMs = 0L;

    public CoopevidaServicio() {
        this.dao = new CoopevidaDAO();
    }

    public CoopevidaServicio(CoopevidaDAO dao) {
        this.dao = dao;
    }

    // Indica si el inicio de sesión está bloqueado en este momento (R2)
    public synchronized boolean estaInicioBloqueado() {
        return System.currentTimeMillis() < bloqueadoHastaEpochMs;
    }

    // Segundos que faltan para que termine el bloqueo (0 si no hay bloqueo)
    public synchronized int obtenerSegundosRestantesBloqueo() {
        long restanteMs = bloqueadoHastaEpochMs - System.currentTimeMillis();
        if (restanteMs <= 0) {
            return 0;
        }
        return (int) Math.ceil(restanteMs / 1000.0);
    }

    // Cantidad de intentos fallidos seguidos hasta ahora
    public synchronized int getIntentosFallidosConsecutivos() {
        return intentosFallidosConsecutivos;
    }

    /**
     * Inicio de sesión (R1, R2, R8 y R9). Pasos:
     *   1. Si el usuario o la contraseña están vacíos, se avisa sin consultar la base de datos.
     *   2. Se busca el usuario y se compara la contraseña con su hash PBKDF2.
     *   3. Si falla, se muestra M01, se suma un intento y se registra LOGIN_FALLIDO.
     *      Al quinto intento se bloquea 15 segundos y se registra BLOQUEO_INICIO.
     *   4. Si es correcta, el contador vuelve a 0 y se registra LOGIN_EXITOSO.
     * Al final, la contraseña se borra de memoria (se llena el arreglo con ceros).
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
                    // Usuario inexistente: se calcula PBKDF2 igual, para que el tiempo de respuesta
                    // no revele si el usuario existe
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

            } catch (IllegalArgumentException e) {
                // M01 o mensaje de campo vacío: se muestran tal cual
                throw e;
            } catch (SQLException | RuntimeException e) {
                // R9: cualquier otro error es técnico y el usuario solo ve M02
                throw manejarErrorTecnico(usuarioLimpio, e);
            }
        } finally {
            if (contrasena != null) {
                Arrays.fill(contrasena, '\0');
            }
        }
    }

    /**
     * Sesión → Cambiar mi contraseña (todos los roles, permiso SESION_CAMBIAR_CLAVE).
     * Pide la contraseña actual para confirmar que es la misma persona, valida la nueva
     * (12 a 128 caracteres) y guarda un hash PBKDF2 nuevo, con sal nueva (R1 y R2).
     */
    public void cambiarContrasena(Usuario sesion, char[] contrasenaActual,
                                  char[] contrasenaNueva, char[] confirmarContrasenaNueva) {
        try {
            // 1. Verificar permiso del rol (R3)
            verificarPermisoConBitacora(sesion, Permiso.SESION_CAMBIAR_CLAVE, "Cambiar contraseña");

            // 2. Validar entradas por lista blanca (R5)
            Validaciones.validarCambioContrasena(contrasenaActual, contrasenaNueva, confirmarContrasenaNueva);

            // 3. Revisar la contraseña actual contra su hash y guardar el hash de la nueva
            try {
                String hashActual = dao.obtenerHashPorId(sesion.getId());
                if (hashActual == null || !Cripto.verificarContrasena(contrasenaActual, hashActual)) {
                    throw new IllegalArgumentException("El campo 'Contraseña actual' no coincide con la contraseña del usuario.");
                }

                String nuevoHash = Cripto.hashContrasena(contrasenaNueva);
                dao.actualizarHashContrasena(sesion.getId(), nuevoHash);
            } catch (IllegalArgumentException | AccesoDenegadoException e) {
                throw e;
            } catch (SQLException | RuntimeException e) {
                // R9: cualquier otro error es técnico y el usuario solo ve M02
                throw manejarErrorTecnico(nombreDeSesion(sesion), e);
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
     * Registrar movimiento, primer paso: el Ejecutivo escribe la cédula y ve el nombre
     * y el saldo actual del asociado antes de registrar el depósito o retiro.
     */
    public Cuenta obtenerResumenCuentaParaMovimiento(Usuario sesion, String cedula) {
        try {
            // 1. Verificar permiso MOVIMIENTO_REGISTRAR (R3)
            verificarPermisoConBitacora(sesion, Permiso.MOVIMIENTO_REGISTRAR,
                    "Resumen cuenta para movimiento: cedula=" + valorSeguro(cedula));

            // 2. Validar cédula por lista blanca (R5)
            String cedulaLimpia = Validaciones.validarCedula(cedula);

            // 3. Consultar cuenta y descifrar saldo (R6)
            Cuenta cuenta = dao.buscarCuentaPorCedula(cedulaLimpia);
            if (cuenta == null) {
                throw new IllegalArgumentException("No existe ningún asociado con la cédula indicada.");
            }
            BigDecimal saldoActual = Cripto.descifrar(cuenta.getSaldoCifrado());
            cuenta.setSaldo(saldoActual);
            return cuenta;
        } catch (IllegalArgumentException | AccesoDenegadoException e) {
            throw e;
        } catch (SQLException | RuntimeException e) {
            // R9: cualquier otro error es técnico y el usuario solo ve M02
            throw manejarErrorTecnico(nombreDeSesion(sesion), e);
        }
    }

    /**
     * Cuentas → Registrar movimiento (Ejecutivo, permiso MOVIMIENTO_REGISTRAR).
     * Valida los datos, revisa que un retiro no supere el saldo, cifra el monto y el
     * nuevo saldo, y guarda ambos en una sola transacción. En la bitácora queda
     * MOVIMIENTO_REGISTRADO sin el monto ni el saldo. Devuelve el nuevo saldo.
     */
    public BigDecimal registrarMovimiento(Usuario sesion, String cedula, String tipo,
                                          String montoTexto, String referencia) {
        try {
            // 1. Verificar permiso del rol (R3)
            verificarPermisoConBitacora(sesion, Permiso.MOVIMIENTO_REGISTRAR,
                    "Registrar movimiento: cedula=" + valorSeguro(cedula));

            // 2. Validar entradas por lista blanca (R5)
            String cedulaLimpia = Validaciones.validarCedula(cedula);
            String tipoNormalizado = Validaciones.validarTipoMovimiento(tipo);
            BigDecimal monto = Validaciones.validarMonto(montoTexto);
            String referenciaLimpia = Validaciones.validarReferencia(referencia);

            // 3. Regla del negocio: un retiro no puede superar el saldo actual
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

            // R5 (rango): si el nuevo saldo es tan grande que cifrado no cabe en la base de datos,
            // se avisa al usuario y no se guarda nada.
            if (nuevoSaldo.toPlainString().length() > LONGITUD_MAXIMA_SALDO) {
                throw new IllegalArgumentException(
                        "El campo 'Monto' haría que el saldo de la cuenta supere el máximo permitido.");
            }

            // 4. R6: el monto y el nuevo saldo se guardan cifrados
            byte[] montoCifrado = Cripto.cifrar(monto);
            byte[] nuevoSaldoCifrado = Cripto.cifrar(nuevoSaldo);

            // 5. Se guarda el movimiento y el nuevo saldo juntos: o se guardan los dos o ninguno.
            // También se envía el saldo cifrado que se leyó al inicio: si otro ejecutivo cambió
            // el saldo mientras tanto, no se guarda nada. Así dos retiros al mismo tiempo no
            // pueden dejar la cuenta en negativo.
            dao.registrarMovimientoYActualizarSaldo(
                    cuenta.getId(),
                    tipoNormalizado,
                    montoCifrado,
                    referenciaLimpia,
                    sesion.getId(),
                    nuevoSaldoCifrado,
                    cuenta.getSaldoCifrado()
            );

            // 6. R8: bitácora con cédula, tipo y referencia, NUNCA con monto ni saldo
            String detalleBitacora = "cedula=" + cedulaLimpia
                    + ", tipo=" + tipoNormalizado
                    + ", referencia=" + referenciaLimpia;
            registrarBitacoraSeguro(sesion.getNombreUsuario(),
                    EVENTO_MOVIMIENTO_REGISTRADO, detalleBitacora, RESULTADO_EXITO);

            return nuevoSaldo;
        } catch (IllegalArgumentException | AccesoDenegadoException e) {
            // Dato inválido o sin permiso: el usuario ve el mensaje del campo o de acceso denegado
            throw e;
        } catch (SQLException | RuntimeException e) {
            // 7. R9: cualquier otro error es técnico y el usuario solo ve M02
            throw manejarErrorTecnico(nombreDeSesion(sesion), e);
        }
    }

    /**
     * Cuentas → Consultar cuenta / Mi cuenta. Es una sola operación que cambia según el rol:
     *   - Ejecutivo (CUENTA_VER): escribe la cédula de cualquier asociado.
     *   - Asociado (CUENTA_VER_PROPIA): no escribe nada; se usa el asociado de su sesión.
     *     Si alguien intenta pedir la cédula de otra persona, se responde "acceso denegado"
     *     (sin decir si esa cédula existe) y se registra ACCESO_DENEGADO (R3 y R8).
     *   - Cualquier otro rol: acceso denegado.
     */
    public Cuenta consultarCuenta(Usuario sesion, String cedulaSolicitada) {
        try {
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
                String cedulaLimpia = Validaciones.validarCedula(cedulaSolicitada);

                // 3. R6: el saldo y los montos se descifran solo para mostrarlos
                Cuenta cuenta = dao.buscarCuentaPorCedula(cedulaLimpia);
                if (cuenta == null) {
                    throw new IllegalArgumentException("No se encontró ninguna cuenta para la cédula indicada.");
                }
                descifrarCuentaYMovimientos(cuenta);
                return cuenta;

            } else if (sesion.getRol() == Rol.ASOCIADO) {
                // 1. Verificar permiso CUENTA_VER_PROPIA (R3)
                verificarPermisoConBitacora(sesion, Permiso.CUENTA_VER_PROPIA, "Consultar mi cuenta");

                if (sesion.getAsociadoId() == null) {
                    registrarBitacoraSeguro(sesion.getNombreUsuario(), EVENTO_ACCESO_DENEGADO,
                            "Usuario asociado sin asociado_id vinculado", RESULTADO_DENEGADO);
                    throw new AccesoDenegadoException("Acceso denegado: no tiene una cuenta vinculada.");
                }
                // Se guarda como int para comparar números (con Integer se compararían objetos)
                int asociadoIdSesion = sesion.getAsociadoId();

                Cuenta cuentaPropia = dao.buscarCuentaPorAsociadoId(asociadoIdSesion);
                if (cuentaPropia == null) {
                    throw new AccesoDenegadoException("Acceso denegado: no fue posible acceder a la cuenta.");
                }

                // R3 (pertenencia): un asociado solo puede ver su propia cuenta.
                // Se rechaza si la cuenta no es del asociado de la sesión, o si la solicitud
                // trae una cédula distinta a la suya (alguien que modificó la petición).
                if (cuentaPropia.getAsociadoId() != asociadoIdSesion
                        || (cedulaSolicitada != null && !cedulaSolicitada.isBlank()
                            && !cedulaSolicitada.trim().equals(cuentaPropia.getCedulaAsociado()))) {
                    registrarBitacoraSeguro(sesion.getNombreUsuario(), EVENTO_ACCESO_DENEGADO,
                            "Intento de consultar cuenta ajena: cedula=" + valorSeguro(cedulaSolicitada),
                            RESULTADO_DENEGADO);
                    throw new AccesoDenegadoException("Acceso denegado: solo puede consultar su propia cuenta.");
                }

                descifrarCuentaYMovimientos(cuentaPropia);
                return cuentaPropia;

            } else {
                // Otro rol (por ejemplo, el Administrador): no puede ver cuentas
                registrarBitacoraSeguro(sesion.getNombreUsuario(), EVENTO_ACCESO_DENEGADO,
                        "Operación CUENTA_VER no permitida para rol " + sesion.getRol().getNombre()
                        + " (dato=" + valorSeguro(cedulaSolicitada) + ")",
                        RESULTADO_DENEGADO);
                throw new AccesoDenegadoException("Acceso denegado: su rol no tiene permiso para consultar cuentas.");
            }
        } catch (IllegalArgumentException | AccesoDenegadoException e) {
            throw e;
        } catch (SQLException | RuntimeException e) {
            // R9: error técnico (base de datos, dato cifrado alterado, etc.) → solo M02
            throw manejarErrorTecnico(nombreDeSesion(sesion), e);
        }
    }

    // Opción "Mi cuenta" del Asociado: no envía cédula, se usa la de su sesión
    public Cuenta consultarMiCuenta(Usuario sesion) {
        return consultarCuenta(sesion, null);
    }

    // R6: descifra el saldo y el monto de cada movimiento para mostrarlos
    private void descifrarCuentaYMovimientos(Cuenta cuenta) throws SQLException {
        cuenta.setSaldo(Cripto.descifrar(cuenta.getSaldoCifrado()));
        List<Movimiento> movimientos = dao.listarMovimientosPorCuenta(cuenta.getId());
        for (Movimiento m : movimientos) {
            m.setMonto(Cripto.descifrar(m.getMontoCifrado()));
        }
        cuenta.setMovimientos(movimientos);
    }

    // Administración → Usuarios: lista de usuarios (permiso USUARIO_VER, solo Administrador)
    public List<Usuario> listarUsuarios(Usuario sesion) {
        try {
            verificarPermisoConBitacora(sesion, Permiso.USUARIO_VER, "Listar usuarios");
            return dao.listarUsuarios();
        } catch (IllegalArgumentException | AccesoDenegadoException e) {
            throw e;
        } catch (SQLException | RuntimeException e) {
            // R9: cualquier otro error es técnico y el usuario solo ve M02
            throw manejarErrorTecnico(nombreDeSesion(sesion), e);
        }
    }

    // Administración → Usuarios: asociados que aún no tienen usuario, solo cédula y nombre
    // (permiso ASOCIADO_VINCULAR). El Administrador no ve saldos ni otros datos.
    public List<Asociado> listarAsociadosSinUsuario(Usuario sesion) {
        try {
            verificarPermisoConBitacora(sesion, Permiso.ASOCIADO_VINCULAR, "Listar asociados sin usuario");
            return dao.listarAsociadosSinUsuario();
        } catch (IllegalArgumentException | AccesoDenegadoException e) {
            throw e;
        } catch (SQLException | RuntimeException e) {
            // R9: cualquier otro error es técnico y el usuario solo ve M02
            throw manejarErrorTecnico(nombreDeSesion(sesion), e);
        }
    }

    /**
     * Administración → Usuarios: crear usuario (permiso USUARIO_CREAR, y ASOCIADO_VINCULAR
     * si el rol es Asociado). Genera una contraseña inicial aleatoria de 14 caracteres,
     * guarda solo su hash y la devuelve para mostrarla una única vez.
     * En la bitácora queda USUARIO_CREADO con el nombre, nunca con la contraseña.
     */
    public String crearUsuario(Usuario sesion, String nombreUsuario, String rolNombre, Integer asociadoId) {
        try {
            // 1. Verificar permiso USUARIO_CREAR (R3)
            verificarPermisoConBitacora(sesion, Permiso.USUARIO_CREAR,
                    "Crear usuario: " + valorSeguro(nombreUsuario));

            // 2. Validar entradas por lista blanca (R5)
            String usuarioLimpio = Validaciones.validarNombreUsuario(nombreUsuario);

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

            // 3. Reglas del negocio: el nombre no se repite y el asociado no tiene ya un usuario
            if (dao.existeNombreUsuario(usuarioLimpio)) {
                throw new IllegalArgumentException("El 'Nombre de usuario' indicado ya existe.");
            }
            if (rolNuevo == Rol.ASOCIADO && !dao.asociadoDisponibleParaVincular(asociadoId)) {
                throw new IllegalArgumentException("El 'Asociado vinculado' no existe o ya tiene un usuario asignado.");
            }

            // 4. R1: se guarda solo el hash de la contraseña inicial, nunca el texto
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
        } catch (IllegalArgumentException | AccesoDenegadoException e) {
            throw e;
        } catch (SQLException | RuntimeException e) {
            // R9: cualquier otro error es técnico y el usuario solo ve M02
            throw manejarErrorTecnico(nombreDeSesion(sesion), e);
        }
    }

    // R3 y R8: revisa el permiso con ControlAcceso. Si se niega, deja ACCESO_DENEGADO
    // en la bitácora y detiene la operación.
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

    /**
     * R9: cuando algo falla por un error técnico, el usuario solo ve el mensaje M02 con un
     * código de referencia (por ejemplo A3F9). El detalle del error se imprime en la terminal
     * con ese mismo código, nunca en la ventana, para no darle pistas a un atacante.
     * En la bitácora queda ERROR_SISTEMA solo con el código y el tipo de error.
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

    /**
     * R8: agrega un registro a la bitácora (la aplicación solo puede insertar, nunca leer,
     * modificar ni borrar).
     *   - Se quitan los saltos de línea del usuario y del detalle. Si no, alguien podría
     *     escribir un "usuario" con saltos de línea y fingir registros falsos.
     *   - Los textos se recortan al tamaño de la columna; así un usuario muy largo no hace
     *     fallar el registro y el intento fallido siempre queda guardado (R2).
     *   - Si la bitácora falla, la operación sigue y el aviso sale en la terminal.
     * El detalle nunca lleva contraseñas, claves, montos ni saldos: solo identificadores.
     */
    private void registrarBitacoraSeguro(String usuarioNombre, String evento, String detalle, String resultado) {
        try {
            String usuarioLimpio = quitarCaracteresControl(usuarioNombre);
            if (usuarioLimpio.isEmpty()) {
                usuarioLimpio = "(vacío)";
            }
            usuarioLimpio = recortar(usuarioLimpio, LONGITUD_MAXIMA_USUARIO_BITACORA);
            String detalleLimpio = recortar(quitarCaracteresControl(detalle), LONGITUD_MAXIMA_DETALLE_BITACORA);

            dao.insertarBitacora(usuarioLimpio, evento, detalleLimpio, resultado);
        } catch (SQLException | RuntimeException ex) {
            System.err.println("[ADVERTENCIA BITÁCORA] No fue posible escribir en la bitácora: "
                    + ex.getClass().getSimpleName());
            ex.printStackTrace(System.err);
        }
    }

    // Cambia por espacios los saltos de línea, tabuladores y otros caracteres invisibles
    private String quitarCaracteresControl(String valor) {
        if (valor == null) {
            return "";
        }
        return valor.replaceAll("\\p{Cntrl}", " ").trim();
    }

    private String recortar(String valor, int longitudMaxima) {
        return valor.length() > longitudMaxima ? valor.substring(0, longitudMaxima) : valor;
    }

    // Limpia un dato escrito por el usuario antes de ponerlo en la bitácora (máximo 40 caracteres)
    private String valorSeguro(String valor) {
        if (valor == null) {
            return "(nulo)";
        }
        String limpio = quitarCaracteresControl(valor);
        return limpio.length() > 40 ? limpio.substring(0, 40) + "..." : limpio;
    }

    // Nombre del usuario de la sesión para la bitácora ("(desconocido)" si no hay sesión)
    private String nombreDeSesion(Usuario sesion) {
        return (sesion != null && sesion.getNombreUsuario() != null)
                ? sesion.getNombreUsuario()
                : "(desconocido)";
    }
}
