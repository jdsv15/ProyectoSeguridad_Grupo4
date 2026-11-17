package app;

import dao.CoopevidaDAO;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.SQLException;
import seguridad.Cripto;

/**
 * Programa aparte que carga los datos de prueba del final de coopevida_base.sql.
 * Se ejecuta a mano una sola vez (clic derecho → Run File).
 * Hace falta porque el SQL no puede calcular hashes ni cifrar: aquí las contraseñas
 * se guardan con PBKDF2 (R1) y los saldos y montos cifrados con AES-GCM (R6).
 */
public class CargaInicial {

    // Inserta todo en una transacción. Si ya hay usuarios, no hace nada y devuelve false.
    public static boolean ejecutarCargaInicial() throws SQLException {
        CoopevidaDAO dao = new CoopevidaDAO();
        if (dao.contarUsuarios() > 0) {
            return false;
        }

        try (Connection conn = dao.obtenerConexion()) {
            conn.setAutoCommit(false);
            try {
                // 1. Los 6 usuarios de prueba: se guarda el hash de cada contraseña (R1)
                insertarUsuario(dao, conn, 1, "admin1", "Admin1-Coop#2026", 1, null);
                insertarUsuario(dao, conn, 2, "ejecutivo1", "Ejec1-Coop#2026", 2, null);
                insertarUsuario(dao, conn, 3, "ejecutivo2", "Ejec2-Coop#2026", 2, null);
                insertarUsuario(dao, conn, 4, "asociado1", "Asoc1-Coop#2026", 3, 1);
                insertarUsuario(dao, conn, 5, "asociado2", "Asoc2-Coop#2026", 3, 2);
                insertarUsuario(dao, conn, 6, "asociado3", "Asoc3-Coop#2026", 3, 3);

                // 2. Las 5 cuentas, con el saldo cifrado (R6)
                insertarCuenta(dao, conn, 1, 1, "650000.00");
                insertarCuenta(dao, conn, 2, 2, "700000.00");
                insertarCuenta(dao, conn, 3, 3, "100000.00");
                insertarCuenta(dao, conn, 4, 4, "0.00");
                insertarCuenta(dao, conn, 5, 5, "0.00");

                // 3. Los 10 movimientos, con el monto cifrado (R6)
                insertarMovimiento(dao, conn, 1L, 1, "deposito", "500000.00", "DEP-0001", "2026-10-05 09:15:00", 2);
                insertarMovimiento(dao, conn, 2L, 1, "deposito", "250000.00", "DEP-0002", "2026-10-12 10:40:00", 2);
                insertarMovimiento(dao, conn, 3L, 1, "retiro", "100000.00", "RET-0001", "2026-10-19 14:05:00", 3);
                insertarMovimiento(dao, conn, 4L, 2, "deposito", "1200000.00", "DEP-0003", "2026-10-06 11:20:00", 2);
                insertarMovimiento(dao, conn, 5L, 2, "retiro", "300000.00", "RET-0002", "2026-10-14 15:30:00", 3);
                insertarMovimiento(dao, conn, 6L, 2, "retiro", "200000.00", "RET-0003", "2026-10-21 08:55:00", 2);
                insertarMovimiento(dao, conn, 7L, 3, "deposito", "75000.50", "DEP-0004", "2026-10-07 13:10:00", 3);
                insertarMovimiento(dao, conn, 8L, 3, "deposito", "24999.50", "DEP-0005", "2026-10-20 16:45:00", 3);
                insertarMovimiento(dao, conn, 9L, 4, "deposito", "2000000.00", "DEP-0006", "2026-10-08 09:00:00", 2);
                insertarMovimiento(dao, conn, 10L, 4, "retiro", "2000000.00", "RET-0004", "2026-10-22 10:10:00", 2);

                conn.commit();
                return true;
            } catch (SQLException | RuntimeException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        }
    }

    private static void insertarUsuario(CoopevidaDAO dao, Connection conn, int id,
                                        String nombreUsuario, String claveEnClaro,
                                        int rolId, Integer asociadoId) throws SQLException {
        String hash = Cripto.hashContrasena(claveEnClaro.toCharArray());
        dao.insertarUsuarioCargaInicial(conn, id, nombreUsuario, hash, rolId, asociadoId);
    }

    private static void insertarCuenta(CoopevidaDAO dao, Connection conn, int id,
                                       int asociadoId, String saldoTexto) throws SQLException {
        byte[] saldoCifrado = Cripto.cifrar(new BigDecimal(saldoTexto));
        dao.insertarCuentaCargaInicial(conn, id, asociadoId, saldoCifrado);
    }

    private static void insertarMovimiento(CoopevidaDAO dao, Connection conn, long id,
                                           int cuentaId, String tipo, String montoTexto,
                                           String referencia, String fechaHora, int usuarioId) throws SQLException {
        byte[] montoCifrado = Cripto.cifrar(new BigDecimal(montoTexto));
        dao.insertarMovimientoCargaInicial(conn, id, cuentaId, tipo, montoCifrado, referencia, fechaHora, usuarioId);
    }

    public static void main(String[] args) {
        System.out.println("=== COOPEVIDA - Programa de Carga Inicial ===");
        try {
            boolean insertado = ejecutarCargaInicial();
            if (insertado) {
                System.out.println("Carga inicial completada exitosamente:");
                System.out.println("  - 6 usuarios insertados con hash PBKDF2WithHmacSHA256 (600 000 iteraciones).");
                System.out.println("  - 5 cuentas insertadas con saldos cifrados mediante AES-GCM (256 bits).");
                System.out.println("  - 10 movimientos insertados con montos cifrados mediante AES-GCM (256 bits).");
            } else {
                System.out.println("Aviso: Los datos de prueba ya se encuentran cargados en la base de datos.");
            }
        } catch (Exception e) {
            System.err.println("Error al ejecutar la carga inicial: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}
