package modelo;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Un depósito o retiro de una cuenta.
 * El DAO solo llena montoCifrado (los bytes guardados en la base). El servicio llena
 * monto (el valor en claro) únicamente cuando hay que mostrarlo (R6).
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
