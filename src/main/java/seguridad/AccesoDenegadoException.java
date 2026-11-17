package seguridad;

/**
 * Excepción que lanza la capa de servicios cuando rechaza una operación (R3):
 * porque el rol no tiene el permiso, o porque los datos pedidos no pertenecen
 * al usuario de la sesión (por ejemplo, un asociado que pide la cuenta de otro).
 */
public class AccesoDenegadoException extends RuntimeException {

    public AccesoDenegadoException(String mensaje) {
        super(mensaje);
    }
}
