package modelo;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Representa la cuenta de ahorro de un asociado y su lista de movimientos.
 * <p>
 * El DAO carga únicamente {@code saldoCifrado} (VARBINARY con AES-GCM) sin
 * conocer el saldo en claro. La capa de servicios descifra el saldo a {@code saldo}
 * cuando se requiere validar un retiro o presentar los datos al usuario.
 */
public class Cuenta {

    private final int id;
    private final int asociadoId;
    private final String cedulaAsociado;
    private final String nombreAsociado;
    private final byte[] saldoCifrado;
    private BigDecimal saldo;
    private List<Movimiento> movimientos;

    public Cuenta(int id, int asociadoId, String cedulaAsociado,
                  String nombreAsociado, byte[] saldoCifrado) {
        this.id = id;
        this.asociadoId = asociadoId;
        this.cedulaAsociado = cedulaAsociado;
        this.nombreAsociado = nombreAsociado;
        this.saldoCifrado = saldoCifrado;
        this.movimientos = new ArrayList<>();
    }

    public int getId() {
        return id;
    }

    public int getAsociadoId() {
        return asociadoId;
    }

    public String getCedulaAsociado() {
        return cedulaAsociado;
    }

    public String getNombreAsociado() {
        return nombreAsociado;
    }

    public byte[] getSaldoCifrado() {
        return saldoCifrado;
    }

    public BigDecimal getSaldo() {
        return saldo;
    }

    public void setSaldo(BigDecimal saldo) {
        this.saldo = saldo;
    }

    public List<Movimiento> getMovimientos() {
        return Collections.unmodifiableList(movimientos);
    }

    public void setMovimientos(List<Movimiento> movimientos) {
        this.movimientos = (movimientos != null) ? new ArrayList<>(movimientos) : new ArrayList<>();
    }
}
