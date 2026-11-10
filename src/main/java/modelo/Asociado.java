package modelo;

/**
 * Representa los datos básicos de un asociado sin usuario asignado,
 * utilizados únicamente en la operación ASOCIADO_VINCULAR (solo cédula y nombre).
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
