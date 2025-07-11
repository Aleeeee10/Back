const MYSQLHOST = 'localhost';
const MYSQLUSER = 'root';
const MYSQLPASSWORD = '';
const MYSQLDATABASE = 'futbolsocial';
const MYSQLPORT = '3306';
const MYSQL_URI = process.env.MYSQL_URI ?? '';
const MONGO_URI = 'mongodb://localhost:27017/socialsoccer';

// Exportar las variables de configuración
module.exports = {
    MYSQLHOST,
    MYSQLUSER,
    MYSQLPASSWORD,
    MYSQLDATABASE,
    MYSQLPORT,
    MYSQL_URI,
    MONGO_URI
};

