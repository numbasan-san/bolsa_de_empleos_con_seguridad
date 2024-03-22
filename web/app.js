const express = require('express');
const app = express();
const path = require('path');
const handlebars = require('express-handlebars');
const multer = require('multer');
const { v4: uuidv4 } = require("uuid");
const session = require('express-session');
const flash = require('connect-flash');
const fs = require('fs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const CSRF = require('csurf');
const xss = require('xss');

// Middleware para protección CSRF
const csrfProtection = CSRF({ cookie: true });

// Importa las funciones de ayuda desde helpers.js
const helpers = require('./utils/helpers/helpers');

//ROUTERS
const index = require('./routers/index');
const page404 = require('./routers/404');
const poster = require('./routers/poster');
const job = require('./routers/job');
const admin = require('./routers/admin');
const login = require('./routers/login');
const account = require('./routers/account');

//MODELS 
const locals = require('./middlewares/locals');
const isAdmin = require('./middlewares/isAdmin');
const isPoster = require('./middlewares/isPoster');

//SETTINGS

// Configuración del motor de plantillas Handlebars
app.engine('hbs', handlebars({
    defaultLayout: 'main-layout',
    layoutsDir: 'views/layout',
    extname: 'hbs',
    helpers: {
        compare: helpers.compare,
        sum: helpers.sum,
        min: helpers.min,
        date: helpers.date
    }
}));
app.set('views', "views");
app.set('view engine', 'hbs');

// Configuración de archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));

// Configuración de multer para manejo de archivos
const fileStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "images");
    },
    filename: (req, file, cb) => {
        cb(null, uuidv4() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: fileStorage }).single("logo");

// Middleware para manejar cookies
app.use(cookieParser());

// Middleware para manejar bodies de solicitud
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Configuración de middleware de sesiones y flash
app.use(session({ secret: 'anything', resave: true, saveUninitialized: false }));
app.use(flash());


// Middleware para evitar ataques XSS
app.use((req, res, next) => {
    for (const key in req.body) {
        req.body[key] = xss(req.body[key]);
    }
    next();
});

// Middleware para registro y monitoreo de eventos de seguridad
app.use((req, res, next) => {
    const logFilePath = 'security_log.txt';
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${req.method} ${req.url} - ${req.ip}\n`; // Incluye también la IP del cliente

    fs.appendFile(logFilePath, logMessage, (err) => {
        if (err) {
            console.error('Error al escribir en el archivo de registro:', err);
            return res.status(500).send('Error interno del servidor');
        }
        next();
    });
});

//MIDLEWARES
app.use(locals);
app.use(index);
app.use(login);
app.use(account);
app.use('/admin', upload, isAdmin, admin);
app.use('/poster', upload, isPoster, poster);
app.use(job);

// Configuración de middleware para detectar posibles incidentes de seguridad
app.use((req, res, next) => {
    const logFilePath = 'security_log.txt';

    // Lógica para analizar los registros en busca de eventos sospechosos y responder en consecuencia
    fs.readFile(logFilePath, 'utf8', (err, data) => {
        if (err) {
            console.error('Error al leer el archivo de registro:', err);
            return next();
        }

        const suspiciousKeywords = ['ataque', 'intruso', 'hack'];

        if (data) {
            const lines = data.split('\n');
            const suspiciousEvents = lines.filter(line => suspiciousKeywords.some(keyword => line.includes(keyword)));

            if (suspiciousEvents.length > 0) {
                console.log('\x1b[31m%s\x1b[0m', '¡Posible incidente detectado!'); // Resalta el mensaje en rojo
                suspiciousEvents.forEach(event => {
                    console.log('Evento sospechoso:', event);
                });
                res.status(403).send('Posible incidente de seguridad detectado');
            } else {
                console.log('No se han detectado incidentes de seguridad.');
                next();
            }
        } else {
            next();
        }
    });
});

// Middleware para prevenir ataques SSRF y otras vulnerabilidades
app.use((req, res, next) => {
    const whitelist = []; // Lista blanca de dominios permitidos
    const requestedUrl = new URL(req.url, `http://${req.headers.host}`);

    if (!whitelist.includes(requestedUrl.hostname)) {
        return res.status(403).send('Acceso no autorizado a este recurso.');
    }

    next();
});

// Middleware para manejar rutas no encontradas
app.use(page404);

// Iniciar el servidor
app.listen(5001, () => {
    console.log('Servidor en funcionamiento en el puerto 5001');
});
