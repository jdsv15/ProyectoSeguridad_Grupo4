package app;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Punto de entrada principal de la aplicación de escritorio COOPEVIDA (paquete {@code app}).
 * <p>
 * Inicia la interfaz gráfica {@link LoginFrame}.
 */
public class Main {

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // Si falla el Look & Feel del sistema, se mantiene el predeterminado de Swing
        }

        // Si la base de datos ya fue creada con coopevida_base.sql pero aún no se ha
        // corrido CargaInicial manualmente, intenta cargarla de forma transparente.
        try {
            if (CargaInicial.ejecutarCargaInicial()) {
                System.out.println("[COOPEVIDA] Datos de prueba cargados automáticamente por CargaInicial.");
            }
        } catch (Exception ex) {
            // Si la BD no está disponible aún, el control de errores M02 actuará al iniciar sesión
            System.err.println("[AVISO INICIO] No se pudo verificar la carga inicial al arrancar: "
                    + ex.getClass().getSimpleName());
        }

        SwingUtilities.invokeLater(() -> {
            LoginFrame loginFrame = new LoginFrame();
            loginFrame.setVisible(true);
        });
    }
}
