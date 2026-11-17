package app;

import java.math.BigDecimal;
import java.time.format.DateTimeFormatter;
import java.util.List;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;
import modelo.Asociado;
import modelo.Cuenta;
import modelo.Movimiento;
import modelo.Usuario;
import modelo.Usuario.Rol;
import seguridad.AccesoDenegadoException;
import servicio.CoopevidaServicio;

/**
 * Menú principal (capa de interfaz). Se diseña con la pestaña Design de NetBeans.
 * Muestra el usuario y su rol, y solo las pestañas que ese rol puede usar.
 * No decide permisos, no valida reglas y no toca la base de datos: todo lo pide a
 * CoopevidaServicio y solo muestra el resultado o el mensaje.
 */
public class MainFrame extends javax.swing.JFrame {

    // R9: la sesión expira tras 2 minutos sin actividad
    private static final long TIEMPO_MAX_INACTIVIDAD_MS = 2 * 60 * 1000L;
    private static final DateTimeFormatter FORMATO_FECHA = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final CoopevidaServicio servicio;
    private Usuario usuarioSesion;
    private long ultimaActividadMs;

    /**
     * Constructor vacío, solo para el diseñador de NetBeans.
     * No crea ninguna sesión: si alguien abre esta ventana sin iniciar sesión,
     * cualquier botón lo devuelve al login (ante la duda, se niega el acceso).
     */
    public MainFrame() {
        this.servicio = null;
        this.usuarioSesion = null;
        initComponents();
        setLocationRelativeTo(null);
        lblUsuarioRol.setText("Sin sesión activa");
    }

    // Abre el menú para el usuario que acaba de iniciar sesión
    public MainFrame(CoopevidaServicio servicio, Usuario usuarioSesion) {
        this.servicio = servicio;
        this.usuarioSesion = usuarioSesion;
        this.ultimaActividadMs = System.currentTimeMillis();
        initComponents();
        setLocationRelativeTo(null);
        configurarSegunRol();
    }

    /**
     * R9: se llama al inicio de cada botón. Si pasaron más de 2 minutos desde la acción
     * anterior, la acción no se hace, se borran los datos de la sesión y se vuelve al login.
     */
    private boolean verificarActividadSesion() {
        if (usuarioSesion == null) {
            volverAlLogin();
            return false;
        }
        long ahora = System.currentTimeMillis();
        if (ahora - ultimaActividadMs > TIEMPO_MAX_INACTIVIDAD_MS) {
            usuarioSesion = null;
            JOptionPane.showMessageDialog(this,
                    "Su sesión ha expirado tras 2 minutos de inactividad. Por favor, inicie sesión nuevamente.",
                    "Sesión expirada", JOptionPane.WARNING_MESSAGE);
            volverAlLogin();
            return false;
        }
        ultimaActividadMs = ahora;
        return true;
    }

    private void volverAlLogin() {
        usuarioSesion = null;
        // Si la ventana se abrió sin servicio (constructor del diseñador), se crea uno nuevo
        LoginFrame login = (servicio != null) ? new LoginFrame(servicio) : new LoginFrame();
        login.setVisible(true);
        this.dispose();
    }

    /**
     * Quita las pestañas que el rol no puede usar. Esto es solo comodidad para el usuario:
     * la seguridad real está en el servicio, que vuelve a revisar el permiso (R3).
     */
    private void configurarSegunRol() {
        lblUsuarioRol.setText("Usuario: " + usuarioSesion.getNombreUsuario()
                + "   |   Rol: " + usuarioSesion.getRol().getNombre());

        Rol rol = usuarioSesion.getRol();
        if (rol == Rol.ADMINISTRADOR) {
            jTabbedPane1.remove(pnlRegistrarMovimiento);
            jTabbedPane1.remove(pnlConsultarCuenta);
            cargarDatosAdministracionUsuarios();
        } else if (rol == Rol.EJECUTIVO) {
            jTabbedPane1.remove(pnlUsuarios);
            jTabbedPane1.setTitleAt(jTabbedPane1.indexOfComponent(pnlConsultarCuenta), "Cuentas: Consultar cuenta");
        } else if (rol == Rol.ASOCIADO) {
            jTabbedPane1.remove(pnlRegistrarMovimiento);
            jTabbedPane1.remove(pnlUsuarios);
            int idxCuenta = jTabbedPane1.indexOfComponent(pnlConsultarCuenta);
            if (idxCuenta >= 0) {
                jTabbedPane1.setTitleAt(idxCuenta, "Cuentas: Mi cuenta");
            }
            lblConCedula.setVisible(false);
            txtConCedula.setVisible(false);
            btnConsultarCuenta.setText("Actualizar mi cuenta");
            cargarMiCuentaAsociado();
        }
    }

    private void cargarMiCuentaAsociado() {
        try {
            Cuenta cuenta = servicio.consultarMiCuenta(usuarioSesion);
            mostrarDatosCuentaEnTabla(cuenta);
        } catch (IllegalArgumentException | AccesoDenegadoException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Acceso a cuenta", JOptionPane.WARNING_MESSAGE);
        } catch (IllegalStateException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Error del sistema", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void mostrarDatosCuentaEnTabla(Cuenta cuenta) {
        lblConDatosAsociado.setText("Cédula: " + cuenta.getCedulaAsociado()
                + "   |   Asociado: " + cuenta.getNombreAsociado());
        lblConSaldoActual.setText("Saldo actual: ₡" + cuenta.getSaldo().toPlainString());

        DefaultTableModel modeloTabla = (DefaultTableModel) tblMovimientos.getModel();
        modeloTabla.setRowCount(0);
        for (Movimiento m : cuenta.getMovimientos()) {
            String fecha = (m.getFechaHora() != null) ? m.getFechaHora().format(FORMATO_FECHA) : "";
            String tipo = "deposito".equalsIgnoreCase(m.getTipo()) ? "Depósito" : "Retiro";
            String monto = "₡" + m.getMonto().toPlainString();
            modeloTabla.addRow(new Object[]{fecha, tipo, m.getReferencia(), monto});
        }
    }

    private void cargarDatosAdministracionUsuarios() {
        try {
            List<Usuario> usuarios = servicio.listarUsuarios(usuarioSesion);
            DefaultTableModel modeloTabla = (DefaultTableModel) tblUsuarios.getModel();
            modeloTabla.setRowCount(0);
            for (Usuario u : usuarios) {
                String cedula = (u.getCedulaAsociado() != null) ? u.getCedulaAsociado() : "-";
                modeloTabla.addRow(new Object[]{u.getNombreUsuario(), u.getRol().getNombre(), cedula});
            }

            cargarComboAsociadosSinUsuario();
            actualizarEstadoComboAsociado();
        } catch (IllegalArgumentException | AccesoDenegadoException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Administración de usuarios", JOptionPane.WARNING_MESSAGE);
        } catch (IllegalStateException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Error del sistema", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void cargarComboAsociadosSinUsuario() {
        cmbAsociadoVincular.removeAllItems();
        List<Asociado> disponibles = servicio.listarAsociadosSinUsuario(usuarioSesion);
        for (Asociado a : disponibles) {
            cmbAsociadoVincular.addItem(a);
        }
    }

    private void actualizarEstadoComboAsociado() {
        String rolSel = (String) cmbNuevoRol.getSelectedItem();
        boolean esAsociado = "Asociado".equalsIgnoreCase(rolSel);
        cmbAsociadoVincular.setEnabled(esAsociado);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        pnlEncabezado = new javax.swing.JPanel();
        lblUsuarioRol = new javax.swing.JLabel();
        btnCerrarSesion = new javax.swing.JButton();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        pnlRegistrarMovimiento = new javax.swing.JPanel();
        lblMovCedula = new javax.swing.JLabel();
        txtMovCedula = new javax.swing.JTextField();
        btnBuscarCuentaMov = new javax.swing.JButton();
        lblMovAsociadoInfo = new javax.swing.JLabel();
        lblMovTipo = new javax.swing.JLabel();
        cmbMovTipo = new javax.swing.JComboBox<>();
        lblMovMonto = new javax.swing.JLabel();
        txtMovMonto = new javax.swing.JTextField();
        lblMovReferencia = new javax.swing.JLabel();
        txtMovReferencia = new javax.swing.JTextField();
        btnRegistrarMovimiento = new javax.swing.JButton();
        pnlConsultarCuenta = new javax.swing.JPanel();
        lblConCedula = new javax.swing.JLabel();
        txtConCedula = new javax.swing.JTextField();
        btnConsultarCuenta = new javax.swing.JButton();
        lblConDatosAsociado = new javax.swing.JLabel();
        lblConSaldoActual = new javax.swing.JLabel();
        jScrollPaneMovimientos = new javax.swing.JScrollPane();
        tblMovimientos = new javax.swing.JTable();
        pnlUsuarios = new javax.swing.JPanel();
        jScrollPaneUsuarios = new javax.swing.JScrollPane();
        tblUsuarios = new javax.swing.JTable();
        btnRefrescarUsuarios = new javax.swing.JButton();
        lblSubtituloCrearUsuario = new javax.swing.JLabel();
        lblNuevoUsuario = new javax.swing.JLabel();
        txtNuevoUsuario = new javax.swing.JTextField();
        lblNuevoRol = new javax.swing.JLabel();
        cmbNuevoRol = new javax.swing.JComboBox<>();
        lblAsociadoVincular = new javax.swing.JLabel();
        cmbAsociadoVincular = new javax.swing.JComboBox<>();
        btnCrearUsuario = new javax.swing.JButton();
        pnlCambiarClave = new javax.swing.JPanel();
        lblClaveActual = new javax.swing.JLabel();
        txtClaveActual = new javax.swing.JPasswordField();
        lblClaveNueva = new javax.swing.JLabel();
        txtClaveNueva = new javax.swing.JPasswordField();
        lblClaveConfirmar = new javax.swing.JLabel();
        txtClaveConfirmar = new javax.swing.JPasswordField();
        btnCambiarClave = new javax.swing.JButton();
        lblReglaClave = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Cooperativa COOPEVIDA - Menú Principal");

        lblUsuarioRol.setFont(new java.awt.Font("SansSerif", 1, 13)); // NOI18N
        lblUsuarioRol.setText("Usuario: - | Rol: -");

        btnCerrarSesion.setText("Cerrar sesión");
        btnCerrarSesion.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCerrarSesionActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlEncabezadoLayout = new javax.swing.GroupLayout(pnlEncabezado);
        pnlEncabezado.setLayout(pnlEncabezadoLayout);
        pnlEncabezadoLayout.setHorizontalGroup(
            pnlEncabezadoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlEncabezadoLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(lblUsuarioRol, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(btnCerrarSesion)
                .addContainerGap())
        );
        pnlEncabezadoLayout.setVerticalGroup(
            pnlEncabezadoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlEncabezadoLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlEncabezadoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblUsuarioRol)
                    .addComponent(btnCerrarSesion))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        lblMovCedula.setText("Cédula del asociado (9 dígitos):");

        btnBuscarCuentaMov.setText("Ver nombre y saldo actual");
        btnBuscarCuentaMov.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnBuscarCuentaMovActionPerformed(evt);
            }
        });

        lblMovAsociadoInfo.setFont(new java.awt.Font("SansSerif", 1, 12)); // NOI18N
        lblMovAsociadoInfo.setText("Asociado: (consulte primero la cédula) | Saldo actual: -");

        lblMovTipo.setText("Tipo de movimiento:");

        cmbMovTipo.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Depósito", "Retiro" }));

        lblMovMonto.setText("Monto (₡):");

        lblMovReferencia.setText("Referencia (máx. 20 caract. letras/números/guion):");

        btnRegistrarMovimiento.setText("Registrar movimiento");
        btnRegistrarMovimiento.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRegistrarMovimientoActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlRegistrarMovimientoLayout = new javax.swing.GroupLayout(pnlRegistrarMovimiento);
        pnlRegistrarMovimiento.setLayout(pnlRegistrarMovimientoLayout);
        pnlRegistrarMovimientoLayout.setHorizontalGroup(
            pnlRegistrarMovimientoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlRegistrarMovimientoLayout.createSequentialGroup()
                .addGap(24, 24, 24)
                .addGroup(pnlRegistrarMovimientoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(lblMovAsociadoInfo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(pnlRegistrarMovimientoLayout.createSequentialGroup()
                        .addGroup(pnlRegistrarMovimientoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblMovCedula)
                            .addComponent(lblMovTipo)
                            .addComponent(lblMovMonto)
                            .addComponent(lblMovReferencia))
                        .addGap(18, 18, 18)
                        .addGroup(pnlRegistrarMovimientoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addGroup(pnlRegistrarMovimientoLayout.createSequentialGroup()
                                .addComponent(txtMovCedula, javax.swing.GroupLayout.PREFERRED_SIZE, 140, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(btnBuscarCuentaMov))
                            .addComponent(cmbMovTipo, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(txtMovMonto)
                            .addComponent(txtMovReferencia)
                            .addComponent(btnRegistrarMovimiento, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(0, 52, Short.MAX_VALUE)))
                .addContainerGap())
        );
        pnlRegistrarMovimientoLayout.setVerticalGroup(
            pnlRegistrarMovimientoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlRegistrarMovimientoLayout.createSequentialGroup()
                .addGap(22, 22, 22)
                .addGroup(pnlRegistrarMovimientoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblMovCedula)
                    .addComponent(txtMovCedula, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnBuscarCuentaMov))
                .addGap(18, 18, 18)
                .addComponent(lblMovAsociadoInfo)
                .addGap(22, 22, 22)
                .addGroup(pnlRegistrarMovimientoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblMovTipo)
                    .addComponent(cmbMovTipo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(16, 16, 16)
                .addGroup(pnlRegistrarMovimientoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblMovMonto)
                    .addComponent(txtMovMonto, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(16, 16, 16)
                .addGroup(pnlRegistrarMovimientoLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblMovReferencia)
                    .addComponent(txtMovReferencia, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(24, 24, 24)
                .addComponent(btnRegistrarMovimiento, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(115, Short.MAX_VALUE))
        );

        jTabbedPane1.addTab("Cuentas: Registrar movimiento", pnlRegistrarMovimiento);

        lblConCedula.setText("Cédula del asociado (9 dígitos):");

        btnConsultarCuenta.setText("Consultar cuenta");
        btnConsultarCuenta.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnConsultarCuentaActionPerformed(evt);
            }
        });

        lblConDatosAsociado.setFont(new java.awt.Font("SansSerif", 1, 12)); // NOI18N
        lblConDatosAsociado.setText("Cédula: -   |   Asociado: -");

        lblConSaldoActual.setFont(new java.awt.Font("SansSerif", 1, 14)); // NOI18N
        lblConSaldoActual.setText("Saldo actual: ₡0.00");

        tblMovimientos.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Fecha y hora", "Tipo", "Referencia", "Monto (₡)"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jScrollPaneMovimientos.setViewportView(tblMovimientos);

        javax.swing.GroupLayout pnlConsultarCuentaLayout = new javax.swing.GroupLayout(pnlConsultarCuenta);
        pnlConsultarCuenta.setLayout(pnlConsultarCuentaLayout);
        pnlConsultarCuentaLayout.setHorizontalGroup(
            pnlConsultarCuentaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlConsultarCuentaLayout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addGroup(pnlConsultarCuentaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPaneMovimientos, javax.swing.GroupLayout.DEFAULT_SIZE, 668, Short.MAX_VALUE)
                    .addComponent(lblConDatosAsociado, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(lblConSaldoActual, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(pnlConsultarCuentaLayout.createSequentialGroup()
                        .addComponent(lblConCedula)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(txtConCedula, javax.swing.GroupLayout.PREFERRED_SIZE, 160, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(btnConsultarCuenta)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addGap(16, 16, 16))
        );
        pnlConsultarCuentaLayout.setVerticalGroup(
            pnlConsultarCuentaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlConsultarCuentaLayout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addGroup(pnlConsultarCuentaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblConCedula)
                    .addComponent(txtConCedula, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnConsultarCuenta))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(lblConDatosAsociado)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lblConSaldoActual)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPaneMovimientos, javax.swing.GroupLayout.DEFAULT_SIZE, 248, Short.MAX_VALUE)
                .addGap(16, 16, 16))
        );

        jTabbedPane1.addTab("Cuentas: Consultar cuenta", pnlConsultarCuenta);

        tblUsuarios.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Nombre de usuario", "Rol", "Cédula del asociado vinculado"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jScrollPaneUsuarios.setViewportView(tblUsuarios);

        btnRefrescarUsuarios.setText("Actualizar lista");
        btnRefrescarUsuarios.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRefrescarUsuariosActionPerformed(evt);
            }
        });

        lblSubtituloCrearUsuario.setFont(new java.awt.Font("SansSerif", 1, 12)); // NOI18N
        lblSubtituloCrearUsuario.setText("Crear nuevo usuario (genera contraseña inicial aleatoria de 14 caracteres)");

        lblNuevoUsuario.setText("Nombre de usuario (4-20 caract. minúsculas/números/./_):");

        lblNuevoRol.setText("Rol:");

        cmbNuevoRol.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Administrador", "Ejecutivo", "Asociado" }));
        cmbNuevoRol.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmbNuevoRolActionPerformed(evt);
            }
        });

        lblAsociadoVincular.setText("Asociado sin usuario (solo si rol es Asociado):");

        btnCrearUsuario.setText("Crear usuario");
        btnCrearUsuario.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCrearUsuarioActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlUsuariosLayout = new javax.swing.GroupLayout(pnlUsuarios);
        pnlUsuarios.setLayout(pnlUsuariosLayout);
        pnlUsuariosLayout.setHorizontalGroup(
            pnlUsuariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlUsuariosLayout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addGroup(pnlUsuariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPaneUsuarios, javax.swing.GroupLayout.DEFAULT_SIZE, 668, Short.MAX_VALUE)
                    .addGroup(pnlUsuariosLayout.createSequentialGroup()
                        .addComponent(lblSubtituloCrearUsuario)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(btnRefrescarUsuarios))
                    .addGroup(pnlUsuariosLayout.createSequentialGroup()
                        .addGroup(pnlUsuariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblNuevoUsuario)
                            .addComponent(lblNuevoRol)
                            .addComponent(lblAsociadoVincular))
                        .addGap(18, 18, 18)
                        .addGroup(pnlUsuariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(txtNuevoUsuario)
                            .addComponent(cmbNuevoRol, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(cmbAsociadoVincular, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnCrearUsuario, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
                .addGap(16, 16, 16))
        );
        pnlUsuariosLayout.setVerticalGroup(
            pnlUsuariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlUsuariosLayout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addComponent(jScrollPaneUsuarios, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlUsuariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblSubtituloCrearUsuario)
                    .addComponent(btnRefrescarUsuarios))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlUsuariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblNuevoUsuario)
                    .addComponent(txtNuevoUsuario, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlUsuariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblNuevoRol)
                    .addComponent(cmbNuevoRol, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlUsuariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblAsociadoVincular)
                    .addComponent(cmbAsociadoVincular, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(btnCrearUsuario, javax.swing.GroupLayout.PREFERRED_SIZE, 32, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(22, Short.MAX_VALUE))
        );

        jTabbedPane1.addTab("Administración: Usuarios", pnlUsuarios);

        lblClaveActual.setText("Contraseña actual:");

        lblClaveNueva.setText("Contraseña nueva (12 a 128 caracteres):");

        lblClaveConfirmar.setText("Confirmar contraseña nueva:");

        btnCambiarClave.setText("Guardar nueva contraseña");
        btnCambiarClave.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCambiarClaveActionPerformed(evt);
            }
        });

        lblReglaClave.setText("Se generará un nuevo hash PBKDF2 con sal aleatoria única.");

        javax.swing.GroupLayout pnlCambiarClaveLayout = new javax.swing.GroupLayout(pnlCambiarClave);
        pnlCambiarClave.setLayout(pnlCambiarClaveLayout);
        pnlCambiarClaveLayout.setHorizontalGroup(
            pnlCambiarClaveLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlCambiarClaveLayout.createSequentialGroup()
                .addGap(32, 32, 32)
                .addGroup(pnlCambiarClaveLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(lblReglaClave)
                    .addGroup(pnlCambiarClaveLayout.createSequentialGroup()
                        .addGroup(pnlCambiarClaveLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblClaveActual)
                            .addComponent(lblClaveNueva)
                            .addComponent(lblClaveConfirmar))
                        .addGap(24, 24, 24)
                        .addGroup(pnlCambiarClaveLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(txtClaveActual)
                            .addComponent(txtClaveNueva)
                            .addComponent(txtClaveConfirmar)
                            .addComponent(btnCambiarClave, javax.swing.GroupLayout.DEFAULT_SIZE, 240, Short.MAX_VALUE))))
                .addContainerGap(184, Short.MAX_VALUE))
        );
        pnlCambiarClaveLayout.setVerticalGroup(
            pnlCambiarClaveLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlCambiarClaveLayout.createSequentialGroup()
                .addGap(28, 28, 28)
                .addComponent(lblReglaClave)
                .addGap(24, 24, 24)
                .addGroup(pnlCambiarClaveLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblClaveActual)
                    .addComponent(txtClaveActual, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(pnlCambiarClaveLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblClaveNueva)
                    .addComponent(txtClaveNueva, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(pnlCambiarClaveLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblClaveConfirmar)
                    .addComponent(txtClaveConfirmar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(26, 26, 26)
                .addComponent(btnCambiarClave, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(142, Short.MAX_VALUE))
        );

        jTabbedPane1.addTab("Sesión: Cambiar mi contraseña", pnlCambiarClave);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(pnlEncabezado, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jTabbedPane1)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(pnlEncabezado, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jTabbedPane1)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnCerrarSesionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCerrarSesionActionPerformed
        volverAlLogin();
    }//GEN-LAST:event_btnCerrarSesionActionPerformed

    private void btnBuscarCuentaMovActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnBuscarCuentaMovActionPerformed
        if (!verificarActividadSesion()) {
            return;
        }
        String cedula = txtMovCedula.getText().trim();
        try {
            Cuenta cuenta = servicio.obtenerResumenCuentaParaMovimiento(usuarioSesion, cedula);
            lblMovAsociadoInfo.setText("Asociado: " + cuenta.getNombreAsociado()
                    + "   |   Saldo actual: ₡" + cuenta.getSaldo().toPlainString());
        } catch (IllegalArgumentException | AccesoDenegadoException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Consulta de cuenta", JOptionPane.WARNING_MESSAGE);
        } catch (IllegalStateException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Error del sistema", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnBuscarCuentaMovActionPerformed

    private void btnRegistrarMovimientoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRegistrarMovimientoActionPerformed
        if (!verificarActividadSesion()) {
            return;
        }
        String cedula = txtMovCedula.getText().trim();
        String tipo = (String) cmbMovTipo.getSelectedItem();
        String monto = txtMovMonto.getText().trim();
        String referencia = txtMovReferencia.getText().trim();

        try {
            BigDecimal nuevoSaldo = servicio.registrarMovimiento(usuarioSesion, cedula, tipo, monto, referencia);
            lblMovAsociadoInfo.setText("Cédula: " + cedula + "   |   Nuevo saldo: ₡" + nuevoSaldo.toPlainString());
            txtMovMonto.setText("");
            txtMovReferencia.setText("");
            JOptionPane.showMessageDialog(this,
                    "Movimiento registrado exitosamente.\nNuevo saldo de la cuenta: ₡" + nuevoSaldo.toPlainString(),
                    "Movimiento registrado", JOptionPane.INFORMATION_MESSAGE);
        } catch (IllegalArgumentException | AccesoDenegadoException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "No se pudo registrar el movimiento", JOptionPane.WARNING_MESSAGE);
        } catch (IllegalStateException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Error del sistema", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnRegistrarMovimientoActionPerformed

    private void btnConsultarCuentaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnConsultarCuentaActionPerformed
        if (!verificarActividadSesion()) {
            return;
        }
        try {
            Cuenta cuenta;
            if (usuarioSesion.getRol() == Rol.ASOCIADO) {
                cuenta = servicio.consultarMiCuenta(usuarioSesion);
            } else {
                String cedula = txtConCedula.getText().trim();
                cuenta = servicio.consultarCuenta(usuarioSesion, cedula);
            }
            mostrarDatosCuentaEnTabla(cuenta);
        } catch (IllegalArgumentException | AccesoDenegadoException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Consulta de cuenta", JOptionPane.WARNING_MESSAGE);
        } catch (IllegalStateException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Error del sistema", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnConsultarCuentaActionPerformed

    private void btnRefrescarUsuariosActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRefrescarUsuariosActionPerformed
        if (!verificarActividadSesion()) {
            return;
        }
        cargarDatosAdministracionUsuarios();
    }//GEN-LAST:event_btnRefrescarUsuariosActionPerformed

    private void cmbNuevoRolActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmbNuevoRolActionPerformed
        actualizarEstadoComboAsociado();
    }//GEN-LAST:event_cmbNuevoRolActionPerformed

    private void btnCrearUsuarioActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCrearUsuarioActionPerformed
        if (!verificarActividadSesion()) {
            return;
        }
        String nombreUsuario = txtNuevoUsuario.getText().trim();
        String rolNombre = (String) cmbNuevoRol.getSelectedItem();
        Integer asociadoId = null;

        if ("Asociado".equalsIgnoreCase(rolNombre)) {
            Asociado seleccionado = (Asociado) cmbAsociadoVincular.getSelectedItem();
            if (seleccionado != null) {
                asociadoId = seleccionado.getId();
            }
        }

        try {
            String contrasenaInicial = servicio.crearUsuario(usuarioSesion, nombreUsuario, rolNombre, asociadoId);
            txtNuevoUsuario.setText("");
            cargarDatosAdministracionUsuarios();

            // Mostrar la contraseña inicial una única vez en un campo seleccionable para entregarla al usuario
            JTextField campoClave = new JTextField(contrasenaInicial);
            campoClave.setEditable(false);
            Object[] mensaje = {
                "Usuario '" + nombreUsuario + "' creado exitosamente.",
                "Entregue esta contraseña inicial al usuario (se muestra una única vez):",
                campoClave
            };
            JOptionPane.showMessageDialog(this, mensaje,
                    "Usuario creado - Contraseña inicial", JOptionPane.INFORMATION_MESSAGE);
        } catch (IllegalArgumentException | AccesoDenegadoException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "No se pudo crear el usuario", JOptionPane.WARNING_MESSAGE);
        } catch (IllegalStateException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Error del sistema", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnCrearUsuarioActionPerformed

    private void btnCambiarClaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCambiarClaveActionPerformed
        if (!verificarActividadSesion()) {
            return;
        }
        char[] actual = txtClaveActual.getPassword();
        char[] nueva = txtClaveNueva.getPassword();
        char[] confirmar = txtClaveConfirmar.getPassword();

        txtClaveActual.setText("");
        txtClaveNueva.setText("");
        txtClaveConfirmar.setText("");

        try {
            servicio.cambiarContrasena(usuarioSesion, actual, nueva, confirmar);
            JOptionPane.showMessageDialog(this,
                    "Su contraseña ha sido actualizada exitosamente.",
                    "Cambio de contraseña", JOptionPane.INFORMATION_MESSAGE);
        } catch (IllegalArgumentException | AccesoDenegadoException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Cambio de contraseña", JOptionPane.WARNING_MESSAGE);
        } catch (IllegalStateException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Error del sistema", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnCambiarClaveActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnBuscarCuentaMov;
    private javax.swing.JButton btnCambiarClave;
    private javax.swing.JButton btnCerrarSesion;
    private javax.swing.JButton btnConsultarCuenta;
    private javax.swing.JButton btnCrearUsuario;
    private javax.swing.JButton btnRefrescarUsuarios;
    private javax.swing.JButton btnRegistrarMovimiento;
    private javax.swing.JComboBox<Asociado> cmbAsociadoVincular;
    private javax.swing.JComboBox<String> cmbMovTipo;
    private javax.swing.JComboBox<String> cmbNuevoRol;
    private javax.swing.JScrollPane jScrollPaneMovimientos;
    private javax.swing.JScrollPane jScrollPaneUsuarios;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JLabel lblAsociadoVincular;
    private javax.swing.JLabel lblClaveActual;
    private javax.swing.JLabel lblClaveConfirmar;
    private javax.swing.JLabel lblClaveNueva;
    private javax.swing.JLabel lblConCedula;
    private javax.swing.JLabel lblConDatosAsociado;
    private javax.swing.JLabel lblConSaldoActual;
    private javax.swing.JLabel lblMovAsociadoInfo;
    private javax.swing.JLabel lblMovCedula;
    private javax.swing.JLabel lblMovMonto;
    private javax.swing.JLabel lblMovReferencia;
    private javax.swing.JLabel lblMovTipo;
    private javax.swing.JLabel lblNuevoRol;
    private javax.swing.JLabel lblNuevoUsuario;
    private javax.swing.JLabel lblReglaClave;
    private javax.swing.JLabel lblSubtituloCrearUsuario;
    private javax.swing.JLabel lblUsuarioRol;
    private javax.swing.JPanel pnlCambiarClave;
    private javax.swing.JPanel pnlConsultarCuenta;
    private javax.swing.JPanel pnlEncabezado;
    private javax.swing.JPanel pnlRegistrarMovimiento;
    private javax.swing.JPanel pnlUsuarios;
    private javax.swing.JTable tblMovimientos;
    private javax.swing.JTable tblUsuarios;
    private javax.swing.JPasswordField txtClaveActual;
    private javax.swing.JPasswordField txtClaveConfirmar;
    private javax.swing.JPasswordField txtClaveNueva;
    private javax.swing.JTextField txtConCedula;
    private javax.swing.JTextField txtMovCedula;
    private javax.swing.JTextField txtMovMonto;
    private javax.swing.JTextField txtMovReferencia;
    private javax.swing.JTextField txtNuevoUsuario;
    // End of variables declaration//GEN-END:variables
}
