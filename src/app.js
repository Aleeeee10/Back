require('dotenv').config();
const express = require('express');
const cors = require('cors'); // 1. IMPORTA CORS AL PRINCIPIO

const app = express();

// 2. COLOCA CORS COMO PRIMER MIDDLEWARE
app.use(cors({
  origin: 'http://localhost:5173', // URL de tu frontend
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const morgan = require('morgan');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const flash = require('connect-flash');
const MySQLStore = require('express-mysql-session')(session);
const fileUpload = require('express-fileupload');
const helmet = require('helmet');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const witson = require('winston');

const { MYSQLHOST, MYSQLUSER, MYSQLPASSWORD, MYSQLDATABASE, MYSQLPORT } = require('./keys');
require('./lib/passport');

// helmet dar seguridad al sistema base a como se envia se extrae la informacion de difrentes entronos
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                ...helmet.contentSecurityPolicy.getDefaultDirectives(),
                "script-src": [
                    "'self'",
                    "'unsafe-inline'",
                    "'unsafe-eval'",
                    "https://maps.googleapis.com",
                    "https://cdnjs.cloudflare.com",
                    "https://cdn.jsdelivr.net",
                    "https://unpkg.com"
                ],
                "style-src": [
                    "'self'",
                    "'unsafe-inline'",
                    "https://fonts.googleapis.com",
                    "https://cdn.jsdelivr.net"
                ],
                "img-src": [
                    "'self'",
                    "data:",
                    "blob:",
                    "https://maps.gstatic.com",
                    "https://*.googleapis.com"
                ],
                "connect-src": [
                    "'self'",
                    "https://maps.googleapis.com",
                    "https://www.bitaldatax.com",
                    "https://www.cardscanner.co/es/image-to-text"
                ],
                "frame-src": ["'self'", "blob:", "https://www.google.com"],
                "object-src": ["'none'"],
                "default-src": ["'self'"]
            }
        },
        referrerPolicy: { policy: "strict-origin-when-cross-origin" }
    })
);


// sesiones mysqlstore
const mysqlStore = {
    host: MYSQLHOST, // <-- Error de escritura, debería ser 'host'
    port: MYSQLPORT,
    user: MYSQLUSER,
    password: MYSQLPASSWORD,
    database: MYSQLDATABASE,
    createDatabaseTable: true,
}

const sessionStore = new MySQLStore(mysqlStore);

app.use(session({
    secret: process.env.SESSION_SECRET || 'app segura',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
}))

// Winston logger (ya lo tienes configurado)
const logger = witson.createLogger({
    level: 'info',
    format: witson.format.combine(
        witson.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        witson.format.errors({ stack: true }),
        witson.format.printf(info => `${info.timestamp} [${info.level}] ${info.message} ${info.stack || ''}`)
    ),
    transports: [
        new witson.transports.File({
            filename: 'app.log',
            level: 'info',
            maxsize: 5242880,
            maxFiles: 5,
        })
    ],
    exceptionHandlers: [
        new witson.transports.File({ filename: 'app.log' })
    ]
});

// Log de inicio de servidor
app.set('port', process.env.PORT || 3000);

// Log de conexión a base de datos relacional (MySQL/Sequelize)
const db = require('../src/dataBase/dataBase.orm');
if (db.sequelize && db.sequelize.authenticate) {
    db.sequelize.authenticate()
        .then(() => logger.info('Conexión a la base de datos MySQL establecida correctamente.'))
        .catch(err => logger.error('Error al conectar a la base de datos MySQL: ' + err.stack));

    // 👉 Agrega este bloque para capturar errores de sincronización
    db.sequelize.sync()
  .then(async () => {
    logger.info('Sincronización de la base de datos completada.');

    // ✅ Ejecutar creación de roles después de que Sequelize esté sincronizado
    const initRoles = require('../utils/initRoles');
    await initRoles();
  })
  .catch(err => logger.error('Error al sincronizar la base de datos: ' + err.stack));

}



// Morgan para logs HTTP
const morganStream = {
    write: (message) => {
        logger.info(message.trim());
    }
};
app.use(morgan('combined', { stream: morganStream }));

// Logs en consola si no es producción
if (process.env.NODE_ENV !== 'production') {
    logger.add(new witson.transports.Console({
        format: witson.format.combine(
            witson.format.colorize(),
            witson.format.simple()
        )
    }));
}

// Middleware de errores globales
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    logger.error(`${err.message}\n${err.stack}`);
    if (err.code === 'ValidationError') {
        return res.status(400).json({ error: err.message });
    }
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).send('Invalid CSRF token');
    }
    return res.status(500).send('Internal Server Error');
});

// Captura excepciones no manejadas
process.on('uncaughtException', (error) => {
    logger.error(`Uncaught Exception: ${error.stack}`);
    process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
    logger.error(`Unhandled Rejection at: ${promise}, reason: ${reason.stack || reason}`);
});

// variables globales
// variables globales con protección por si no existe req.flash
app.use((req, res, next) => {
    res.locals.user = req.user || null;

    if (typeof req.flash === 'function') {
        res.locals.success = req.flash('success');
        res.locals.error = req.flash('error');
    } else {
        res.locals.success = [];
        res.locals.error = [];
    }

    next();
});


//midelwar proteccion o token 
const milderwarCsrf = csrf({ cookie: true });
app.use(cookieParser());
app.use(milderwarCsrf)

// Token CSRF para las vistas o rutas
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});


app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// rutas
app.use('/roles', require('./router/rol.router'));
app.use('/teams', require('./router/teams.router'));
app.use('/players', require('./router/players.router'));
app.use('/referees', require('./router/referees.router'));
app.use('/matches', require('./router/matches.router'));
app.use('/news', require('./router/news.router'));
app.use('/standings', require('./router/standings.router'));
app.use('/division', require('./router/division.router'));
app.use('/detalle-division', require('./router/detalleDivision.router'));
app.use('/estadisticas', require('./router/estadisticas.router'));
app.use('/detalle-estadisticas', require('./router/detalleEstadisticas.router'));
app.use('/resultados', require('./router/resultados.router'));
app.use('/detalle-resultados', require('./router/detalleResultados.router'));
app.use('/tarjetas', require('./router/tarjetas.router'));
app.use('/canchas', require('./router/canchas.router'));
app.use('/detalle-jugadores', require('./router/detalleJugadores.router'));
app.use('/auth', require('./router/auth.router'));

// Base de datos MongoDB sincronización
const connectMongoDB = require('./dataBase/dataBase.mongo');
connectMongoDB().then(async () => {
    // Aquí puedes crear colecciones vacías si lo deseas
    try {
        const UserPreferences = require('./model/userPreferences.model');
        await UserPreferences.createCollection();
        // Repite para otros modelos si lo necesitas
        // const OtroModelo = require('./model/otroModelo');
        // await OtroModelo.createCollection();
        console.log('Colecciones de MongoDB listas.');
    } catch (err) {
        console.error('Error creando colecciones en MongoDB:', err);
    }
});

module.exports = app;