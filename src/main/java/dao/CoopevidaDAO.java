package dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import modelo.Asociado;
import modelo.Cuenta;
import modelo.Movimiento;
import modelo.Usuario;
import modelo.Usuario.Rol;
import seguridad.Configuracion;

/**
 * Capa de acceso a datos: aquí está todo el SQL de la aplicación.
 *
 * R4: todas las consultas usan PreparedStatement con signos "?". Lo que escribe el
 *     usuario se envía aparte como dato con setString/setInt, nunca pegado al texto
 *     del SQL. Por eso una entrada como  ' OR '1'='1  se busca tal cual y no cambia
 *     la consulta (no hay inyección SQL).
 * R7: se conecta con el usuario coopevida_app (no root), que solo tiene los permisos
 *     que necesita. Sus credenciales se leen de fuera del código (clase Configuracion).
 * Esta clase no decide permisos ni descifra nada: saldos y montos entran y salen cifrados.
 */
public class CoopevidaDAO {

    // Devuelve el usuario junto con su hash, solo para revisar la contraseña al iniciar sesión.
    // El hash no se guarda en el objeto Usuario de la sesión.
    public static class RegistroAutenticacion {
        private final Usuario usuario;
        private final String hashContrasena;

        public RegistroAutenticacion(Usuario usuario, String hashContrasena) {
            this.usuario = usuario;
            this.hashContrasena = hashContrasena;
        }

        public Usuario getUsuario() {
            return usuario;
        }

        public String getHashContrasena() {
            return hashContrasena;
        }
    }

    // R7: abre la conexión a MariaDB con el usuario de la aplicación.
    // Las credenciales se leen de fuera del código (variable de entorno o config.properties).
    public Connection obtenerConexion() throws SQLException {
        String url = Configuracion.obtener("COOPEVIDA_DB_URL", "db.url");
        String user = Configuracion.obtener("COOPEVIDA_DB_USER", "db.user");
        String pass = Configuracion.obtener("COOPEVIDA_DB_PASS", "db.password");

        if (url == null || user == null || pass == null) {
            throw new SQLException("Credenciales de base de datos no configuradas en config.properties ni en variables de entorno.");
        }
        return DriverManager.getConnection(url.trim(), user.trim(), pass);
    }

    // R4: el nombre escrito en el login se envía como parámetro, nunca dentro del SQL
    public RegistroAutenticacion buscarUsuarioPorNombre(String nombreUsuario) throws SQLException {
        String sql = "SELECT id, nombre_usuario, hash_contrasena, rol_id, asociado_id "
                   + "FROM usuario WHERE nombre_usuario = ?";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, nombreUsuario);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    int id = rs.getInt("id");
                    String nombre = rs.getString("nombre_usuario");
                    String hash = rs.getString("hash_contrasena");
                    int rolId = rs.getInt("rol_id");
                    int asocRaw = rs.getInt("asociado_id");
                    Integer asociadoId = rs.wasNull() ? null : asocRaw;

                    Usuario usuario = new Usuario(id, nombre, Rol.desdeId(rolId), asociadoId);
                    return new RegistroAutenticacion(usuario, hash);
                }
                return null;
            }
        }
    }

    // Hash actual de la contraseña de un usuario (para el cambio de contraseña)
    public String obtenerHashPorId(int usuarioId) throws SQLException {
        String sql = "SELECT hash_contrasena FROM usuario WHERE id = ?";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, usuarioId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("hash_contrasena");
                }
                return null;
            }
        }
    }

    // Guarda el nuevo hash de la contraseña de un usuario
    public void actualizarHashContrasena(int usuarioId, String nuevoHash) throws SQLException {
        String sql = "UPDATE usuario SET hash_contrasena = ? WHERE id = ?";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, nuevoHash);
            ps.setInt(2, usuarioId);
            ps.executeUpdate();
        }
    }

    // Todos los usuarios con su rol y la cédula del asociado vinculado (si tiene)
    public List<Usuario> listarUsuarios() throws SQLException {
        String sql = "SELECT u.id, u.nombre_usuario, u.rol_id, u.asociado_id, a.cedula "
                   + "FROM usuario u "
                   + "LEFT JOIN asociado a ON u.asociado_id = a.id "
                   + "ORDER BY u.id ASC";
        List<Usuario> lista = new ArrayList<>();
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                int id = rs.getInt("id");
                String nombre = rs.getString("nombre_usuario");
                Rol rol = Rol.desdeId(rs.getInt("rol_id"));
                int asocRaw = rs.getInt("asociado_id");
                Integer asocId = rs.wasNull() ? null : asocRaw;
                String cedula = rs.getString("cedula");
                lista.add(new Usuario(id, nombre, rol, asocId, cedula));
            }
        }
        return lista;
    }

    // Indica si ya existe un usuario con ese nombre
    public boolean existeNombreUsuario(String nombreUsuario) throws SQLException {
        String sql = "SELECT 1 FROM usuario WHERE nombre_usuario = ?";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, nombreUsuario);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    // Asociados que aún no tienen usuario. Solo se leen cédula y nombre (ASOCIADO_VINCULAR).
    public List<Asociado> listarAsociadosSinUsuario() throws SQLException {
        String sql = "SELECT a.id, a.cedula, a.nombre, a.apellidos "
                   + "FROM asociado a "
                   + "LEFT JOIN usuario u ON u.asociado_id = a.id "
                   + "WHERE u.id IS NULL "
                   + "ORDER BY a.cedula ASC";
        List<Asociado> lista = new ArrayList<>();
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                int id = rs.getInt("id");
                String cedula = rs.getString("cedula");
                String nombreCompleto = rs.getString("nombre") + " " + rs.getString("apellidos");
                lista.add(new Asociado(id, cedula, nombreCompleto));
            }
        }
        return lista;
    }

    // Indica si el asociado existe y todavía no tiene usuario
    public boolean asociadoDisponibleParaVincular(int asociadoId) throws SQLException {
        String sql = "SELECT 1 FROM asociado a "
                   + "LEFT JOIN usuario u ON u.asociado_id = a.id "
                   + "WHERE a.id = ? AND u.id IS NULL";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, asociadoId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    // Guarda un usuario nuevo con el hash de su contraseña (nunca la contraseña)
    public void insertarUsuario(String nombreUsuario, String hashContrasena, int rolId, Integer asociadoId) throws SQLException {
        String sql = "INSERT INTO usuario (nombre_usuario, hash_contrasena, rol_id, asociado_id) "
                   + "VALUES (?, ?, ?, ?)";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, nombreUsuario);
            ps.setString(2, hashContrasena);
            ps.setInt(3, rolId);
            if (asociadoId != null) {
                ps.setInt(4, asociadoId);
            } else {
                ps.setNull(4, Types.INTEGER);
            }
            ps.executeUpdate();
        }
    }

    // R4: busca la cuenta por cédula (la cédula va como parámetro). El saldo sale cifrado.
    public Cuenta buscarCuentaPorCedula(String cedula) throws SQLException {
        String sql = "SELECT c.id, c.asociado_id, a.cedula, a.nombre, a.apellidos, c.saldo "
                   + "FROM cuenta c "
                   + "INNER JOIN asociado a ON c.asociado_id = a.id "
                   + "WHERE a.cedula = ?";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, cedula);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    int id = rs.getInt("id");
                    int asocId = rs.getInt("asociado_id");
                    String ced = rs.getString("cedula");
                    String nombreCompleto = rs.getString("nombre") + " " + rs.getString("apellidos");
                    byte[] saldoCifrado = rs.getBytes("saldo");
                    return new Cuenta(id, asocId, ced, nombreCompleto, saldoCifrado);
                }
                return null;
            }
        }
    }

    // Busca la cuenta del asociado de la sesión ("Mi cuenta"). El saldo sale cifrado.
    public Cuenta buscarCuentaPorAsociadoId(int asociadoId) throws SQLException {
        String sql = "SELECT c.id, c.asociado_id, a.cedula, a.nombre, a.apellidos, c.saldo "
                   + "FROM cuenta c "
                   + "INNER JOIN asociado a ON c.asociado_id = a.id "
                   + "WHERE c.asociado_id = ?";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, asociadoId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    int id = rs.getInt("id");
                    int asocId = rs.getInt("asociado_id");
                    String ced = rs.getString("cedula");
                    String nombreCompleto = rs.getString("nombre") + " " + rs.getString("apellidos");
                    byte[] saldoCifrado = rs.getBytes("saldo");
                    return new Cuenta(id, asocId, ced, nombreCompleto, saldoCifrado);
                }
                return null;
            }
        }
    }

    // Movimientos de una cuenta, del más reciente al más antiguo. Los montos salen cifrados.
    public List<Movimiento> listarMovimientosPorCuenta(int cuentaId) throws SQLException {
        String sql = "SELECT id, cuenta_id, tipo, monto, referencia, fecha_hora, usuario_id "
                   + "FROM movimiento "
                   + "WHERE cuenta_id = ? "
                   + "ORDER BY fecha_hora DESC, id DESC";
        List<Movimiento> lista = new ArrayList<>();
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, cuentaId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    long id = rs.getLong("id");
                    int cId = rs.getInt("cuenta_id");
                    String tipo = rs.getString("tipo");
                    byte[] montoCifrado = rs.getBytes("monto");
                    String referencia = rs.getString("referencia");
                    Timestamp ts = rs.getTimestamp("fecha_hora");
                    LocalDateTime fechaHora = (ts != null) ? ts.toLocalDateTime() : null;
                    int usuarioId = rs.getInt("usuario_id");
                    lista.add(new Movimiento(id, cId, tipo, montoCifrado, referencia, fechaHora, usuarioId));
                }
            }
        }
        return lista;
    }

    /**
     * Guarda el movimiento y el nuevo saldo en una transacción: o se guardan los dos o
     * ninguno (si algo falla, rollback deshace todo).
     * El UPDATE solo cambia el saldo si en la base sigue el mismo saldo cifrado que se leyó
     * antes. Si otro movimiento lo cambió en el medio, no se actualiza nada, se deshace
     * todo y se pide intentar de nuevo. Aquí solo se comparan bytes cifrados.
     */
    public void registrarMovimientoYActualizarSaldo(
            int cuentaId,
            String tipo,
            byte[] montoCifrado,
            String referencia,
            int usuarioId,
            byte[] nuevoSaldoCifrado,
            byte[] saldoCifradoLeido) throws SQLException {

        String sqlInsertMov = "INSERT INTO movimiento (cuenta_id, tipo, monto, referencia, usuario_id) "
                            + "VALUES (?, ?, ?, ?, ?)";
        String sqlUpdateCuenta = "UPDATE cuenta SET saldo = ? WHERE id = ? AND saldo = ?";

        try (Connection conn = obtenerConexion()) {
            conn.setAutoCommit(false);
            try (PreparedStatement psMov = conn.prepareStatement(sqlInsertMov);
                 PreparedStatement psCuenta = conn.prepareStatement(sqlUpdateCuenta)) {

                psMov.setInt(1, cuentaId);
                psMov.setString(2, tipo);
                psMov.setBytes(3, montoCifrado);
                psMov.setString(4, referencia);
                psMov.setInt(5, usuarioId);
                psMov.executeUpdate();

                psCuenta.setBytes(1, nuevoSaldoCifrado);
                psCuenta.setInt(2, cuentaId);
                psCuenta.setBytes(3, saldoCifradoLeido);
                int filas = psCuenta.executeUpdate();
                if (filas != 1) {
                    // El saldo cambió desde que se leyó: se deshace también el movimiento insertado
                    conn.rollback();
                    throw new IllegalArgumentException("El saldo de la cuenta cambió, intente de nuevo.");
                }

                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        }
    }

    // R8: agrega un registro a la bitácora. En la base de datos, coopevida_app solo tiene
    // permiso INSERT en esta tabla: no puede leerla, modificarla ni borrarla.
    public void insertarBitacora(String usuarioNombre, String evento, String detalle, String resultado) throws SQLException {
        String sql = "INSERT INTO bitacora (usuario_nombre, evento, detalle, resultado) "
                   + "VALUES (?, ?, ?, ?)";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, usuarioNombre != null ? usuarioNombre : "(desconocido)");
            ps.setString(2, evento);
            ps.setString(3, detalle != null ? detalle : "");
            ps.setString(4, resultado);
            ps.executeUpdate();
        }
    }

    // Cantidad de usuarios. CargaInicial la usa para no cargar los datos de prueba dos veces.
    public int contarUsuarios() throws SQLException {
        String sql = "SELECT COUNT(*) FROM usuario";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        }
    }

    // Carga inicial: inserta un usuario de prueba con su id
    public void insertarUsuarioCargaInicial(Connection conn, int id, String nombreUsuario,
                                            String hashContrasena, int rolId, Integer asociadoId) throws SQLException {
        String sql = "INSERT INTO usuario (id, nombre_usuario, hash_contrasena, rol_id, asociado_id) "
                   + "VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, id);
            ps.setString(2, nombreUsuario);
            ps.setString(3, hashContrasena);
            ps.setInt(4, rolId);
            if (asociadoId != null) {
                ps.setInt(5, asociadoId);
            } else {
                ps.setNull(5, Types.INTEGER);
            }
            ps.executeUpdate();
        }
    }

    // Carga inicial: inserta una cuenta con su saldo ya cifrado
    public void insertarCuentaCargaInicial(Connection conn, int id, int asociadoId, byte[] saldoCifrado) throws SQLException {
        String sql = "INSERT INTO cuenta (id, asociado_id, saldo) VALUES (?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, id);
            ps.setInt(2, asociadoId);
            ps.setBytes(3, saldoCifrado);
            ps.executeUpdate();
        }
    }

    // Carga inicial: inserta un movimiento con su monto ya cifrado y su fecha
    public void insertarMovimientoCargaInicial(Connection conn, long id, int cuentaId, String tipo,
                                               byte[] montoCifrado, String referencia,
                                               String fechaHora, int usuarioId) throws SQLException {
        String sql = "INSERT INTO movimiento (id, cuenta_id, tipo, monto, referencia, fecha_hora, usuario_id) "
                   + "VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, id);
            ps.setInt(2, cuentaId);
            ps.setString(3, tipo);
            ps.setBytes(4, montoCifrado);
            ps.setString(5, referencia);
            ps.setTimestamp(6, Timestamp.valueOf(fechaHora));
            ps.setInt(7, usuarioId);
            ps.executeUpdate();
        }
    }
}
