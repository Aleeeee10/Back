const { createPool } = require("mysql2");
const { promisify } = require("util");
const dotenv = require('dotenv');

dotenv.config();

const {
    MYSQLHOST,
    MYSQLUSER,
    MYSQLPASSWORD,
    MYSQLDATABASE,
    MYSQLPORT,
    MYSQL_URI
} = require("../keys");

let pool;

if (MYSQL_URI) {
    pool = createPool(MYSQL_URI);
} else {
    pool = createPool({
        host: MYSQLHOST,
        user: MYSQLUSER,
        password: MYSQLPASSWORD,
        database: MYSQLDATABASE,
        port: MYSQLPORT,
    });
}

pool.getConnection((err, connection) => {
    if (err) {
        switch (err.code) {
            case 'PROTOCOL_CONNECTION_LOST':
                console.error('Se cerró la conexión a la base de datos');
                break;
            case 'ER_CON_COUNT_ERROR':
                console.error('La base de datos tiene demasiadas conexiones');
                break;
            case 'ECONNREFUSED':
                console.error('La conexión a la base de datos fue rechazada');
                break;
            default:
                console.error('Error inesperado:', err.message);
        }
    }

    if (connection) {
        connection.release();
        console.log('Base de datos conectada');
        return;
    }
});

pool.query = promisify(pool.query);

module.exports = pool;