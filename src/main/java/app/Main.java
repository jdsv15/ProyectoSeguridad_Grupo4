package app;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Punto de inicio de la aplicación: abre la ventana de inicio de sesión (LoginFrame).
 */
public class Main {

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // Si falla el Look & Feel del sistema, se mantiene el predeterminado de Swing
        }

        // Los datos de prueba NO se cargan aquí: CargaInicial es un programa aparte que se
        // ejecuta a mano una sola vez. Así la aplicación nunca siembra usuarios con
        // contraseñas conocidas sin que nadie lo pida.
        SwingUtilities.invokeLater(() -> {
            LoginFrame loginFrame = new LoginFrame();
            loginFrame.setVisible(true);
        });
    }
}
