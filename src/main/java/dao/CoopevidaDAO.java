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
import java.util.Properties;
import modelo.Asociado;
import modelo.Cuenta;
import modelo.Movimiento;
import modelo.Usuario;
import modelo.Usuario.Rol;
import seguridad.Cripto;

/**
 * Capa de acceso a datos (DAO) del sistema COOPEVIDA.
 * <ul>
 *   <li><b>R4 (Prevención de inyección SQL):</b> El 100 % de las consultas utiliza
 *       {@link PreparedStatement} con parámetros {@code ?}. No existe ninguna
 *       concatenación de entradas de usuario en sentencias SQL.</li>
 *   <li><b>R7 (Mínimo privilegio y credenciales externas):</b> Se conecta usando
 *       el usuario de aplicación ({@code coopevida_app}) leyendo las credenciales
 *       desde variables de entorno o desde {@code config.properties}.</li>
 *   <li><b>Separación de responsabilidades:</b> Esta clase nunca cifra ni descifra
 *       montos o saldos; únicamente transfiere los arreglos {@code byte[]} cifrados
 *       hacia y desde las columnas {@code VARBINARY(64)}.</li>
 * </ul>
 */
public class CoopevidaDAO {

    /**
     * Contenedor interno para devolver a la capa de servicios el usuario junto con
     * su hash PBKDF2 únicamente durante la verificación de credenciales.
     */
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

    /**
     * Obtiene una conexión JDBC hacia MariaDB utilizando las credenciales externas
     * configuradas en variables de entorno o en {@code config.properties} (R7).
     */
    public Connection obtenerConexion() throws SQLException {
        Properties props = Cripto.cargarPropiedadesExternas();

        String url = obtenerValorConfig("COOPEVIDA_DB_URL", props, "db.url");
        String user = obtenerValorConfig("COOPEVIDA_DB_USER", props, "db.user");
        String pass = obtenerValorConfig("COOPEVIDA_DB_PASS", props, "db.password");

        if (url == null || user == null || pass == null) {
            throw new SQLException("Credenciales de base de datos no configuradas en config.properties ni en variables de entorno.");
        }
        return DriverManager.getConnection(url.trim(), user.trim(), pass);
    }

    private String obtenerValorConfig(String envName, Properties props, String propName) {
        String val = System.getenv(envName);
        if (val == null || val.isBlank()) {
            val = props.getProperty(propName);
        }
        return (val != null && !val.isBlank()) ? val : null;
    }

    /**
     * Busca un usuario por su {@code nombre_usuario} mediante consulta parametrizada (R4).
     */
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

    /**
     * Obtiene el hash de contraseña actual de un usuario por su identificador.
     */
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

    /**
     * Actualiza el hash PBKDF2 de la contraseña de un usuario (cambiar contraseña).
     */
    public void actualizarHashContrasena(int usuarioId, String nuevoHash) throws SQLException {
        String sql = "UPDATE usuario SET hash_contrasena = ? WHERE id = ?";
        try (Connection conn = obtenerConexion();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, nuevoHash);
            ps.setInt(2, usuarioId);
            ps.executeUpdate();
        }
    }

    /**
     * Lista todos los usuarios registrados con su rol y la cédula del asociado vinculado (si aplica).
     */
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

    /**
     * Verifica si ya existe un usuario con el nombre indicado.
     */
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

    /**
     * Lista únicamente cédula y nombre completo de los asociados que aún no tienen
     * usuario vinculado (operación ASOCIADO_VINCULAR).
     */
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

    /**
     * Comprueba que el asociado exista y aún no tenga usuario vinculado.
     */
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

    /**
     * Inserta un nuevo usuario en la base de datos con su hash PBKDF2.
     */
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

    /**
     * Busca una cuenta por el número de cédula del asociado (9 dígitos).
     * Devuelve la cuenta con su {@code saldoCifrado} sin descifrar.
     */
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

    /**
     * Busca una cuenta por el identificador interno del asociado.
     * Devuelve la cuenta con su {@code saldoCifrado} sin descifrar.
     */
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

    /**
     * Obtiene la lista de movimientos de una cuenta ordenados del más reciente al más antiguo.
     * Los montos se devuelven cifrados ({@code byte[]}) para que la capa de servicios los descifre.
     */
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
     * Registra un movimiento y actualiza el saldo de la cuenta en una única
     * transacción atómica. Si ocurre cualquier fallo, se revierte toda la operación.
     */
    public void registrarMovimientoYActualizarSaldo(
            int cuentaId,
            String tipo,
            byte[] montoCifrado,
            String referencia,
            int usuarioId,
            byte[] nuevoSaldoCifrado) throws SQLException {

        String sqlInsertMov = "INSERT INTO movimiento (cuenta_id, tipo, monto, referencia, usuario_id) "
                            + "VALUES (?, ?, ?, ?, ?)";
        String sqlUpdateCuenta = "UPDATE cuenta SET saldo = ? WHERE id = ?";

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
                int filas = psCuenta.executeUpdate();
                if (filas != 1) {
                    throw new SQLException("No fue posible actualizar el saldo de la cuenta.");
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

    /**
     * Inserta un registro en la bitácora de auditoría de solo inserción (R8).
     * El usuario de base de datos de la aplicación solo posee privilegio INSERT sobre {@code bitacora}.
     */
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

    /**
     * Cuenta la cantidad de usuarios registrados (utilizado por {@code CargaInicial}
     * para verificar si los datos de prueba ya fueron insertados).
     */
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

    /**
     * Inserta un usuario con identificador explícito durante la carga inicial.
     */
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

    /**
     * Inserta una cuenta con identificador explícito y saldo cifrado durante la carga inicial.
     */
    public void insertarCuentaCargaInicial(Connection conn, int id, int asociadoId, byte[] saldoCifrado) throws SQLException {
        String sql = "INSERT INTO cuenta (id, asociado_id, saldo) VALUES (?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, id);
            ps.setInt(2, asociadoId);
            ps.setBytes(3, saldoCifrado);
            ps.executeUpdate();
        }
    }

    /**
     * Inserta un movimiento con identificador, monto cifrado y fecha explícita durante la carga inicial.
     */
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
