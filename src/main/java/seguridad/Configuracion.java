package seguridad;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

/**
 * R6 y R7: lee los datos secretos (clave AES y credenciales de la base de datos)
 * desde fuera del código fuente.
 *
 * Primero busca una variable de entorno y, si no existe, el archivo config.properties.
 * Ese archivo no se sube al repositorio ni va en el .zip (se entrega
 * config.properties.ejemplo). Así nadie que lea el código puede ver la clave.
 */
public final class Configuracion {

    private Configuracion() {
        // Solo tiene métodos estáticos
    }

    // Devuelve el valor configurado, o null si no existe.
    // Ejemplo: obtener("COOPEVIDA_AES_KEY", "aes.key")
    public static String obtener(String variableEntorno, String propiedad) {
        String valor = System.getenv(variableEntorno);
        if (valor == null || valor.isBlank()) {
            valor = leerArchivo().getProperty(propiedad);
        }
        if (valor == null || valor.isBlank()) {
            return null;
        }
        return valor;
    }

    // Lee config.properties de la carpeta del proyecto (o de la ruta indicada con
    // -Dcoopevida.config). Si el archivo no existe, devuelve una lista vacía.
    private static Properties leerArchivo() {
        String ruta = System.getProperty("coopevida.config", "config.properties");
        Properties props = new Properties();
        try (FileInputStream archivo = new FileInputStream(ruta)) {
            props.load(archivo);
        } catch (FileNotFoundException e) {
            // Sin archivo: se usan solo las variables de entorno
        } catch (IOException e) {
            throw new IllegalStateException("No se pudo leer el archivo de configuración externo", e);
        }
        return props;
    }
}
