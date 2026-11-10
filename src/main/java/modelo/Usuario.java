package modelo;

/**
 * Representa al usuario autenticado en el sistema COOPEVIDA o un elemento de la
 * lista de usuarios consultada por el administrador.
 * <p>
 * No almacena el hash de la contraseña en el objeto de sesión para evitar
 * exponer material sensible en memoria durante la sesión activa.
 */
public class Usuario {

    /**
     * Roles fijos definidos por el modelo de negocio y seguridad (R3).
     */
    public enum Rol {
        ADMINISTRADOR(1, "Administrador"),
        EJECUTIVO(2, "Ejecutivo"),
        ASOCIADO(3, "Asociado");

        private final int id;
        private final String nombre;

        Rol(int id, String nombre) {
            this.id = id;
            this.nombre = nombre;
        }

        public int getId() {
            return id;
        }

        public String getNombre() {
            return nombre;
        }

        /**
         * Convierte el identificador numérico de la base de datos en su Rol.
         */
        public static Rol desdeId(int id) {
            for (Rol r : values()) {
                if (r.id == id) {
                    return r;
                }
            }
            throw new IllegalArgumentException("Identificador de rol inválido: " + id);
        }

        /**
         * Convierte el nombre textual del rol en su enumeración correspondiente.
         */
        public static Rol desdeNombre(String nombre) {
            if (nombre == null) {
                throw new IllegalArgumentException("El rol es obligatorio.");
            }
            for (Rol r : values()) {
                if (r.nombre.equalsIgnoreCase(nombre.trim())) {
                    return r;
                }
            }
            throw new IllegalArgumentException("Rol inválido. Debe ser Administrador, Ejecutivo o Asociado.");
        }

        @Override
        public String toString() {
            return nombre;
        }
    }

    private final int id;
    private final String nombreUsuario;
    private final Rol rol;
    private final Integer asociadoId;
    private final String cedulaAsociado;

    public Usuario(int id, String nombreUsuario, Rol rol, Integer asociadoId, String cedulaAsociado) {
        this.id = id;
        this.nombreUsuario = nombreUsuario;
        this.rol = rol;
        this.asociadoId = asociadoId;
        this.cedulaAsociado = cedulaAsociado;
    }

    public Usuario(int id, String nombreUsuario, Rol rol, Integer asociadoId) {
        this(id, nombreUsuario, rol, asociadoId, null);
    }

    public int getId() {
        return id;
    }

    public String getNombreUsuario() {
        return nombreUsuario;
    }

    public Rol getRol() {
        return rol;
    }

    public Integer getAsociadoId() {
        return asociadoId;
    }

    public String getCedulaAsociado() {
        return cedulaAsociado;
    }
}
