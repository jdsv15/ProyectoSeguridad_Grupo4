package modelo;

/**
 * El usuario que inició sesión (la interfaz lo envía en cada llamada al servicio),
 * o una fila de la lista de usuarios que ve el Administrador.
 * No guarda el hash de la contraseña: después del login ya no se necesita.
 */
public class Usuario {

    // R3: los tres roles del enunciado, con el mismo id que en la tabla rol
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

        // Convierte el rol_id de la base de datos en un Rol
        public static Rol desdeId(int id) {
            for (Rol r : values()) {
                if (r.id == id) {
                    return r;
                }
            }
            // El id viene de la base de datos, no de lo que escribe el usuario: si es inválido es
            // un error técnico, y el servicio mostrará M02 sin dar detalles (R9).
            throw new IllegalStateException("Identificador de rol inválido: " + id);
        }

        // Convierte el nombre elegido en pantalla ("Ejecutivo", etc.) en un Rol
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
