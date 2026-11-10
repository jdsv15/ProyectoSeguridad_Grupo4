package seguridad;

/**
 * Excepción de seguridad lanzada por la capa de servicios cuando se rechaza una
 * operación por falta de permiso del rol (RBAC) o por violación de pertenencia
 * de los datos (IDOR / control de acceso roto - R3).
 */
public class AccesoDenegadoException extends RuntimeException {

    public AccesoDenegadoException(String mensaje) {
        super(mensaje);
    }
}
