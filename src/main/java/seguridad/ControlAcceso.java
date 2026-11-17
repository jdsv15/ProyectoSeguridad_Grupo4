package seguridad;

import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import modelo.Usuario;
import modelo.Usuario.Rol;

/**
 * R3: control de acceso por roles.
 *
 * Aquí, y solo aquí, se define qué puede hacer cada rol (la matriz de permisos del
 * enunciado). Cada operación de CoopevidaServicio llama a verificarPermiso antes de
 * hacer cualquier cosa. Ocultar un botón en la ventana no basta, porque la interfaz
 * se puede saltar; esta revisión en el servicio es la que realmente protege.
 */
public final class ControlAcceso {

    // Códigos de operación del enunciado
    public enum Permiso {
        SESION_CAMBIAR_CLAVE,   // Cambiar la propia contraseña (todos los roles)
        USUARIO_VER,            // Listar usuarios (Administrador)
        USUARIO_CREAR,          // Crear usuario (Administrador)
        ASOCIADO_VINCULAR,      // Ver cédula y nombre de asociados sin usuario (Administrador)
        MOVIMIENTO_REGISTRAR,   // Registrar depósito o retiro (Ejecutivo)
        CUENTA_VER,             // Ver la cuenta de cualquier asociado (Ejecutivo)
        CUENTA_VER_PROPIA       // Ver solo la propia cuenta (Asociado)
    }

    // Matriz rol -> permisos. Se arma una sola vez y no se puede cambiar mientras
    // la aplicación corre (por eso se guarda como "unmodifiable").
    private static final Map<Rol, Set<Permiso>> MATRIZ_PERMISOS;

    static {
        EnumMap<Rol, Set<Permiso>> mapa = new EnumMap<>(Rol.class);

        mapa.put(Rol.ADMINISTRADOR, Collections.unmodifiableSet(EnumSet.of(
                Permiso.SESION_CAMBIAR_CLAVE,
                Permiso.USUARIO_VER,
                Permiso.USUARIO_CREAR,
                Permiso.ASOCIADO_VINCULAR
        )));

        mapa.put(Rol.EJECUTIVO, Collections.unmodifiableSet(EnumSet.of(
                Permiso.SESION_CAMBIAR_CLAVE,
                Permiso.MOVIMIENTO_REGISTRAR,
                Permiso.CUENTA_VER
        )));

        mapa.put(Rol.ASOCIADO, Collections.unmodifiableSet(EnumSet.of(
                Permiso.SESION_CAMBIAR_CLAVE,
                Permiso.CUENTA_VER_PROPIA
        )));

        MATRIZ_PERMISOS = Collections.unmodifiableMap(mapa);
    }

    private ControlAcceso() {
        // Solo tiene métodos estáticos
    }

    // Dice si el rol tiene el permiso según la matriz
    public static boolean tienePermiso(Rol rol, Permiso permiso) {
        if (rol == null || permiso == null) {
            return false;
        }
        Set<Permiso> permisosRol = MATRIZ_PERMISOS.get(rol);
        return permisosRol != null && permisosRol.contains(permiso);
    }

    /**
     * R3: si no hay sesión o el rol no tiene el permiso, se lanza AccesoDenegadoException
     * y la operación no se ejecuta. Ante la duda, se niega (fallo seguro).
     */
    public static void verificarPermiso(Usuario usuario, Permiso permiso) {
        if (usuario == null || usuario.getRol() == null || !tienePermiso(usuario.getRol(), permiso)) {
            throw new AccesoDenegadoException("Acceso denegado: no tiene permiso para ejecutar esta operación.");
        }
    }
}
