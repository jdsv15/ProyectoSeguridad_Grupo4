package modelo;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Representa un movimiento financiero (depósito o retiro) asociado a una cuenta.
 * <p>
 * Cumple la separación de capas: la capa DAO únicamente manipula el arreglo de
 * bytes cifrado ({@code montoCifrado}) sin conocer nunca el valor en claro, y la
 * capa de servicios lo descifra a {@code monto} únicamente cuando debe mostrarse
 * a un usuario autorizado.
 */
public class Movimiento {

    private final long id;
    private final int cuentaId;
    private final String tipo;
    private final byte[] montoCifrado;
    private BigDecimal monto;
    private final String referencia;
    private final LocalDateTime fechaHora;
    private final int usuarioId;

    public Movimiento(long id, int cuentaId, String tipo, byte[] montoCifrado,
                      String referencia, LocalDateTime fechaHora, int usuarioId) {
        this.id = id;
        this.cuentaId = cuentaId;
        this.tipo = tipo;
        this.montoCifrado = montoCifrado;
        this.referencia = referencia;
        this.fechaHora = fechaHora;
        this.usuarioId = usuarioId;
    }

    public long getId() {
        return id;
    }

    public int getCuentaId() {
        return cuentaId;
    }

    public String getTipo() {
        return tipo;
    }

    public byte[] getMontoCifrado() {
        return montoCifrado;
    }

    public BigDecimal getMonto() {
        return monto;
    }

    public void setMonto(BigDecimal monto) {
        this.monto = monto;
    }

    public String getReferencia() {
        return referencia;
    }

    public LocalDateTime getFechaHora() {
        return fechaHora;
    }

    public int getUsuarioId() {
        return usuarioId;
    }
}
