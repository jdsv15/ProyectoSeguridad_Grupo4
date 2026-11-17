package modelo;

/**
 * Asociado que todavía no tiene usuario. Solo lleva cédula y nombre, porque es lo
 * único que el Administrador puede ver para vincularlo (ASOCIADO_VINCULAR).
 */
public class Asociado {

    private final int id;
    private final String cedula;
    private final String nombreCompleto;

    public Asociado(int id, String cedula, String nombreCompleto) {
        this.id = id;
        this.cedula = cedula;
        this.nombreCompleto = nombreCompleto;
    }

    public int getId() {
        return id;
    }

    public String getCedula() {
        return cedula;
    }

    public String getNombreCompleto() {
        return nombreCompleto;
    }

    @Override
    public String toString() {
        return cedula + " - " + nombreCompleto;
    }
}
