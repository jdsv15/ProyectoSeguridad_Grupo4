package app;

import javax.swing.JOptionPane;
import javax.swing.Timer;
import modelo.Usuario;
import servicio.CoopevidaServicio;

/**
 * Ventana de inicio de sesión (capa de interfaz). Se diseña con la pestaña Design de NetBeans.
 * La contraseña se escribe en un JPasswordField, así no se ve en pantalla.
 * La revisión del usuario y la contraseña la hace CoopevidaServicio; esta ventana solo
 * muestra el resultado y desactiva los campos durante el bloqueo de 15 segundos (R2).
 */
public class LoginFrame extends javax.swing.JFrame {

    private final CoopevidaServicio servicio;
    private Timer timerBloqueo;

    // Abre el login con un servicio nuevo (al iniciar la aplicación)
    public LoginFrame() {
        this(new CoopevidaServicio());
    }

    // Abre el login con el mismo servicio (al cerrar sesión), para que el contador de
    // intentos fallidos no se reinicie con solo volver a esta ventana
    public LoginFrame(CoopevidaServicio servicio) {
        this.servicio = servicio;
        initComponents();
        setLocationRelativeTo(null);
        getRootPane().setDefaultButton(btnIngresar);
        verificarEstadoBloqueoUI();
    }

    // R2: si el servicio dice que hay bloqueo, se desactivan los campos y cada medio
    // segundo se actualiza la cuenta regresiva hasta que se puedan volver a usar.
    private void verificarEstadoBloqueoUI() {
        if (!servicio.estaInicioBloqueado()) {
            return;
        }
        establecerControlesHabilitados(false);
        actualizarEtiquetaBloqueo();

        if (timerBloqueo != null && timerBloqueo.isRunning()) {
            timerBloqueo.stop();
        }
        timerBloqueo = new Timer(500, e -> {
            if (servicio.estaInicioBloqueado()) {
                actualizarEtiquetaBloqueo();
            } else {
                timerBloqueo.stop();
                establecerControlesHabilitados(true);
                lblEstado.setText("Puede intentar iniciar sesión nuevamente.");
                txtUsuario.requestFocusInWindow();
            }
        });
        timerBloqueo.start();
    }

    private void actualizarEtiquetaBloqueo() {
        int seg = servicio.obtenerSegundosRestantesBloqueo();
        lblEstado.setText("Inicio bloqueado por 5 intentos fallidos. Espere " + seg + " s...");
    }

    private void establecerControlesHabilitados(boolean habilitado) {
        txtUsuario.setEnabled(habilitado);
        txtContrasena.setEnabled(habilitado);
        btnIngresar.setEnabled(habilitado);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        lblTitulo = new javax.swing.JLabel();
        lblSubtitulo = new javax.swing.JLabel();
        lblUsuario = new javax.swing.JLabel();
        txtUsuario = new javax.swing.JTextField();
        lblContrasena = new javax.swing.JLabel();
        txtContrasena = new javax.swing.JPasswordField();
        btnIngresar = new javax.swing.JButton();
        lblEstado = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("COOPEVIDA - Inicio de Sesión");
        setResizable(false);

        lblTitulo.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        lblTitulo.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        lblTitulo.setText("Cooperativa COOPEVIDA");

        lblSubtitulo.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        lblSubtitulo.setText("Sistema de Ahorro - Inicio de Sesión");

        lblUsuario.setText("Usuario:");

        lblContrasena.setText("Contraseña:");

        btnIngresar.setText("Iniciar sesión");
        btnIngresar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnIngresarActionPerformed(evt);
            }
        });

        lblEstado.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        lblEstado.setText("Ingrese sus credenciales.");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(30, 30, 30)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(lblTitulo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(lblSubtitulo, javax.swing.GroupLayout.DEFAULT_SIZE, 320, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblUsuario)
                            .addComponent(lblContrasena))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(txtUsuario)
                            .addComponent(txtContrasena)))
                    .addComponent(btnIngresar, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(lblEstado, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap(30, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(24, 24, 24)
                .addComponent(lblTitulo)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lblSubtitulo)
                .addGap(24, 24, 24)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblUsuario)
                    .addComponent(txtUsuario, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(16, 16, 16)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblContrasena)
                    .addComponent(txtContrasena, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(22, 22, 22)
                .addComponent(btnIngresar, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(lblEstado)
                .addContainerGap(22, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnIngresarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnIngresarActionPerformed
        String usuario = txtUsuario.getText();
        char[] contrasena = txtContrasena.getPassword();
        txtContrasena.setText("");

        try {
            Usuario autenticado = servicio.iniciarSesion(usuario, contrasena);
            if (timerBloqueo != null && timerBloqueo.isRunning()) {
                timerBloqueo.stop();
            }
            MainFrame mainFrame = new MainFrame(servicio, autenticado);
            mainFrame.setVisible(true);
            this.dispose();
        } catch (IllegalArgumentException ex) {
            if (servicio.estaInicioBloqueado()) {
                verificarEstadoBloqueoUI();
            }
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Inicio de sesión", JOptionPane.WARNING_MESSAGE);
        } catch (IllegalStateException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Error del sistema", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnIngresarActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnIngresar;
    private javax.swing.JLabel lblContrasena;
    private javax.swing.JLabel lblEstado;
    private javax.swing.JLabel lblSubtitulo;
    private javax.swing.JLabel lblTitulo;
    private javax.swing.JLabel lblUsuario;
    private javax.swing.JPasswordField txtContrasena;
    private javax.swing.JTextField txtUsuario;
    // End of variables declaration//GEN-END:variables
}
