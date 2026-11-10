package seguridad;

import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import modelo.Usuario;
import modelo.Usuario.Rol;

/**
 * Implementa el control de acceso basado en roles (RBAC - Requisito R3).
 * <p>
 * Define en un único lugar del código el catálogo de permisos ({@link Permiso})
 * y la matriz inmutable de permisos por rol. Toda operación en la capa de
 * servicios invoca {@link #verificarPermiso(Usuario, Permiso)} antes de
 * procesar cualquier solicitud.
 */
public final class ControlAcceso {

    /**
     * Códigos oficiales de operación definidos en el enunciado (R3).
     */
    public enum Permiso {
        /** Cambiar la propia contraseña (todos los roles). */
        SESION_CAMBIAR_CLAVE,
        /** Listar usuarios (solo Administrador). */
        USUARIO_VER,
        /** Crear usuario (solo Administrador). */
        USUARIO_CREAR,
        /** Ver cédula y nombre de asociados sin usuario, solo para vincular (solo Administrador). */
        ASOCIADO_VINCULAR,
        /** Registrar depósito o retiro (solo Ejecutivo). */
        MOVIMIENTO_REGISTRAR,
        /** Ver la cuenta y los movimientos de cualquier asociado (solo Ejecutivo). */
        CUENTA_VER,
        /** Ver la propia cuenta y sus movimientos (solo Asociado). */
        CUENTA_VER_PROPIA
    }

    /**
     * Matriz fija e inmutable de permisos (Rol x Operación).
     */
    private static final Map<Rol, Set<Permiso>> MATRIZ_PERMISOS;

    static {
        EnumMap<Rol, Set<Permiso>> mapa = new EnumMap<>(Rol.class);

        // Administrador: cambiar clave, ver usuarios, crear usuario y vincular asociado
        mapa.put(Rol.ADMINISTRADOR, Collections.unmodifiableSet(EnumSet.of(
                Permiso.SESION_CAMBIAR_CLAVE,
                Permiso.USUARIO_VER,
                Permiso.USUARIO_CREAR,
                Permiso.ASOCIADO_VINCULAR
        )));

        // Ejecutivo: cambiar clave, registrar movimientos y ver cuenta de cualquier asociado
        mapa.put(Rol.EJECUTIVO, Collections.unmodifiableSet(EnumSet.of(
                Permiso.SESION_CAMBIAR_CLAVE,
                Permiso.MOVIMIENTO_REGISTRAR,
                Permiso.CUENTA_VER
        )));

        // Asociado: cambiar clave y ver únicamente su propia cuenta
        mapa.put(Rol.ASOCIADO, Collections.unmodifiableSet(EnumSet.of(
                Permiso.SESION_CAMBIAR_CLAVE,
                Permiso.CUENTA_VER_PROPIA
        )));

        MATRIZ_PERMISOS = Collections.unmodifiableMap(mapa);
    }

    private ControlAcceso() {
        // Clase utilitaria no instanciable
    }

    /**
     * Consulta si un rol posee el permiso indicado según la matriz fija.
     */
    public static boolean tienePermiso(Rol rol, Permiso permiso) {
        if (rol == null || permiso == null) {
            return false;
        }
        Set<Permiso> permisosRol = MATRIZ_PERMISOS.get(rol);
        return permisosRol != null && permisosRol.contains(permiso);
    }

    /**
     * Verifica que el usuario autenticado tenga el permiso requerido.
     * Si no lo tiene, lanza {@link AccesoDenegadoException} (fallo seguro).
     *
     * @param usuario Usuario de la sesión activa.
     * @param permiso Permiso requerido por la operación.
     * @throws AccesoDenegadoException Si el usuario es nulo o su rol no tiene el permiso.
     */
    public static void verificarPermiso(Usuario usuario, Permiso permiso) {
        if (usuario == null || usuario.getRol() == null || !tienePermiso(usuario.getRol(), permiso)) {
            throw new AccesoDenegadoException("Acceso denegado: no tiene permiso para ejecutar esta operación.");
        }
    }
}
