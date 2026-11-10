-- =====================================================================
--  COOPEVIDA - Sistema de ahorro
--  IF0019 Seguridad en Sistemas Informáticos, II Semestre 2026
--  Script base para MariaDB 10.4 o superior (entregado por el docente)
--
--  Qué hace:
--    1. Crea la base de datos `coopevida` (se borra si ya existía).
--    2. Crea las 6 tablas con sus llaves primarias, foráneas y restricciones.
--    3. Crea el usuario de la aplicación con privilegios mínimos.
--    4. Carga los roles y los 5 asociados (la aplicación no registra asociados).
--
--  Cómo ejecutarlo:  mariadb -u root -p < coopevida_base.sql
--
--  QUÉ FALTA (lo hace su grupo)
--    Este script NO incluye usuarios, cuentas ni movimientos, porque sus
--    columnas protegidas deben generarse con el código de su aplicación:
--      * usuario.hash_contrasena  -> hash PBKDF2 de la contraseña (R1)
--      * cuenta.saldo             -> saldo cifrado con AES-GCM (R6)
--      * movimiento.monto         -> monto cifrado con AES-GCM (R6)
--    Al final de este archivo está la lista de datos de prueba que su
--    programa de carga inicial debe insertar. Todos los grupos usan los
--    mismos datos.
--
--  Nota: el usuario de la aplicación solo tiene INSERT sobre la bitácora.
--  Para revisarla, conéctese con otro usuario (por ejemplo, root).
--
--  Pueden modificar este script (columnas, índices, privilegios), siempre que
--  no debiliten ningún requisito de seguridad del enunciado.
-- =====================================================================

DROP DATABASE IF EXISTS coopevida;
CREATE DATABASE coopevida CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE coopevida;

-- ---------------------------------------------------------------------
--  TABLAS
-- ---------------------------------------------------------------------

CREATE TABLE rol (
    id      TINYINT UNSIGNED NOT NULL,
    nombre  VARCHAR(20)      NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_rol_nombre (nombre)
) ENGINE=InnoDB;

CREATE TABLE asociado (
    id        INT UNSIGNED NOT NULL AUTO_INCREMENT,
    cedula    CHAR(9)      NOT NULL,
    nombre    VARCHAR(50)  NOT NULL,
    apellidos VARCHAR(80)  NOT NULL,
    telefono  CHAR(8)      NOT NULL,
    correo    VARCHAR(100) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_asociado_cedula (cedula),
    CONSTRAINT ck_asociado_cedula   CHECK (cedula REGEXP '^[1-9][0-9]{8}$'),
    CONSTRAINT ck_asociado_telefono CHECK (telefono REGEXP '^[245678][0-9]{7}$')
) ENGINE=InnoDB;

-- Regla que se valida en la capa de servicios: un usuario con rol Asociado
-- debe tener asociado_id; los demás roles no lo tienen.
CREATE TABLE usuario (
    id              INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    nombre_usuario  VARCHAR(20)      NOT NULL,
    hash_contrasena VARCHAR(255)     NOT NULL,
    rol_id          TINYINT UNSIGNED NOT NULL,
    asociado_id     INT UNSIGNED     NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_usuario_nombre   (nombre_usuario),
    UNIQUE KEY uq_usuario_asociado (asociado_id),
    CONSTRAINT fk_usuario_rol      FOREIGN KEY (rol_id)      REFERENCES rol (id)       ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_usuario_asociado FOREIGN KEY (asociado_id) REFERENCES asociado (id)  ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

-- saldo: AES-GCM (IV || texto cifrado || etiqueta)
CREATE TABLE cuenta (
    id          INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    asociado_id INT UNSIGNED  NOT NULL,
    saldo       VARBINARY(64) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_cuenta_asociado (asociado_id),
    CONSTRAINT fk_cuenta_asociado FOREIGN KEY (asociado_id) REFERENCES asociado (id) ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

-- monto: AES-GCM (IV || texto cifrado || etiqueta). Nunca se modifica ni se elimina.
CREATE TABLE movimiento (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    cuenta_id  INT UNSIGNED    NOT NULL,
    tipo       ENUM('deposito','retiro') NOT NULL,
    monto      VARBINARY(64)   NOT NULL,
    referencia VARCHAR(20)     NOT NULL,
    fecha_hora DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    usuario_id INT UNSIGNED    NOT NULL,
    PRIMARY KEY (id),
    KEY ix_movimiento_cuenta (cuenta_id, fecha_hora),
    CONSTRAINT fk_movimiento_cuenta  FOREIGN KEY (cuenta_id)  REFERENCES cuenta (id)  ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_movimiento_usuario FOREIGN KEY (usuario_id) REFERENCES usuario (id) ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB;

-- Sin llaves foráneas: guarda el nombre del usuario como texto.
-- Solo se insertan registros (el usuario de la aplicación no tiene UPDATE ni DELETE).
CREATE TABLE bitacora (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    fecha_hora     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    usuario_nombre VARCHAR(50)     NOT NULL,
    evento         VARCHAR(40)     NOT NULL,
    detalle        VARCHAR(255)    NOT NULL DEFAULT '',
    resultado      ENUM('Exito','Fallido','Denegado') NOT NULL,
    PRIMARY KEY (id),
    KEY ix_bitacora_fecha (fecha_hora)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
--  USUARIO DE LA APLICACIÓN (mínimo privilegio)
--  Sin DELETE en ninguna tabla. Asociados: solo lectura.
--  Bitácora: solo INSERT (no puede leerla, modificarla ni borrarla).
-- ---------------------------------------------------------------------
DROP USER IF EXISTS 'coopevida_app'@'localhost';
CREATE USER 'coopevida_app'@'localhost' IDENTIFIED BY 'CambieEstaClave#2026';

GRANT SELECT                  ON coopevida.rol        TO 'coopevida_app'@'localhost';
GRANT SELECT                  ON coopevida.asociado   TO 'coopevida_app'@'localhost';
GRANT SELECT, INSERT, UPDATE  ON coopevida.usuario    TO 'coopevida_app'@'localhost';
GRANT SELECT, INSERT, UPDATE  ON coopevida.cuenta     TO 'coopevida_app'@'localhost';
GRANT SELECT, INSERT          ON coopevida.movimiento TO 'coopevida_app'@'localhost';
GRANT INSERT                  ON coopevida.bitacora   TO 'coopevida_app'@'localhost';
FLUSH PRIVILEGES;

-- ---------------------------------------------------------------------
--  DATOS DE PRUEBA (los que sí se pueden escribir en SQL)
-- ---------------------------------------------------------------------

INSERT INTO rol (id, nombre) VALUES
    (1, 'Administrador'),
    (2, 'Ejecutivo'),
    (3, 'Asociado');

-- Asociados 1 a 3 tienen usuario; el 4 (saldo en cero) y el 5 (sin movimientos) no.
INSERT INTO asociado (id, cedula, nombre, apellidos, telefono, correo) VALUES
    (1, '112340567', 'Ana Lucía', 'Vargas Solano', '88123456', 'ana.vargas@example.com'),
    (2, '205670891', 'Carlos Eduardo', 'Jiménez Arce', '70234567', 'carlos.jimenez@example.com'),
    (3, '304560123', 'María Fernanda', 'Chaves Brenes', '60345678', 'maria.chaves@example.com'),
    (4, '401230456', 'Luis Diego', 'Mora Castillo', '83456789', 'luis.mora@example.com'),
    (5, '503450789', 'Sofía', 'Ramírez Alfaro', '24567890', 'sofia.ramirez@example.com');

-- ---------------------------------------------------------------------
--  DATOS DE PRUEBA QUE DEBE CARGAR SU PROGRAMA DE CARGA INICIAL
--  (no se pueden escribir en SQL: requieren hash y cifrado)
-- ---------------------------------------------------------------------
--
--  USUARIOS (usuario | rol | asociado vinculado | contraseña)
--    1 admin1     | Administrador (rol 1) | -          | Admin1-Coop#2026
--    2 ejecutivo1 | Ejecutivo     (rol 2) | -          | Ejec1-Coop#2026
--    3 ejecutivo2 | Ejecutivo     (rol 2) | -          | Ejec2-Coop#2026
--    4 asociado1  | Asociado      (rol 3) | asociado 1 | Asoc1-Coop#2026
--    5 asociado2  | Asociado      (rol 3) | asociado 2 | Asoc2-Coop#2026
--    6 asociado3  | Asociado      (rol 3) | asociado 3 | Asoc3-Coop#2026
--
--  CUENTAS: una por asociado (cuenta 1 para el asociado 1, y así hasta la 5).
--    El saldo de cada cuenta es la suma de sus movimientos:
--      cuenta 1: 650000.00   cuenta 2: 700000.00   cuenta 3: 100000.00
--      cuenta 4: 0.00        cuenta 5: 0.00
--
--  MOVIMIENTOS (id | cuenta | tipo | monto | referencia | fecha y hora | usuario que lo registra)
--     1 | 1 | deposito | 500000.00  | DEP-0001 | 2026-10-05 09:15:00 | 2
--     2 | 1 | deposito | 250000.00  | DEP-0002 | 2026-10-12 10:40:00 | 2
--     3 | 1 | retiro   | 100000.00  | RET-0001 | 2026-10-19 14:05:00 | 3
--     4 | 2 | deposito | 1200000.00 | DEP-0003 | 2026-10-06 11:20:00 | 2
--     5 | 2 | retiro   | 300000.00  | RET-0002 | 2026-10-14 15:30:00 | 3
--     6 | 2 | retiro   | 200000.00  | RET-0003 | 2026-10-21 08:55:00 | 2
--     7 | 3 | deposito | 75000.50   | DEP-0004 | 2026-10-07 13:10:00 | 3
--     8 | 3 | deposito | 24999.50   | DEP-0005 | 2026-10-20 16:45:00 | 3
--     9 | 4 | deposito | 2000000.00 | DEP-0006 | 2026-10-08 09:00:00 | 2
--    10 | 4 | retiro   | 2000000.00 | RET-0004 | 2026-10-22 10:10:00 | 2
--
--  Recuerde: el monto y el saldo se cifran con AES-GCM (R6), con un IV aleatorio por
--  valor y una clave que NO esté en el código ni en este script, y las contraseñas se guardan
--  con PBKDF2 (R1).
