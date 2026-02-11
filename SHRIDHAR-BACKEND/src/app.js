const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const AppError = require('./utils/AppError');
const routes = require('./routes/v1');
const errorHandler = require('./middlewares/errorHandler');
const { globalLimiter } = require('./middlewares/rateLimit');
const maintenanceMiddleware = require('./middlewares/maintenanceMiddleware');
const passport = require('passport');
require('./config/passport'); // Passport Config

const app = express();

// Trust Proxy for Render/Heroku (Required for Secure Cookies in Prod)
if (process.env.NODE_ENV === 'production') {
    app.enable('trust proxy');
}

// CORS - Must be first
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:5173'];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);

        // In development, allow any localhost/IP origin
        if (process.env.NODE_ENV === 'development') {
            return callback(null, true);
        }

        if (allowedOrigins.indexOf(origin) === -1) {
            return callback(new Error('The CORS policy for this site does not allow access from the specified Origin.'), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'device-remember-token', 'Access-Control-Allow-Origin', 'Origin', 'Accept', 'bypass-tunnel-reminder']
}));

// Security HTTP headers
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginEmbedderPolicy: false
}));

// Passport Init
app.use(passport.initialize());

// Development logging
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}

// Limit requests from same API
app.use('/api', globalLimiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET));

// Data sanitization against XSS attacks
// Data sanitization against XSS attacks
// app.use(xss());

// Data sanitization against NoSQL query injection
app.use((req, res, next) => {
    req.body = mongoSanitize.sanitize(req.body);
    req.params = mongoSanitize.sanitize(req.params);

    if (req.query) {
        mongoSanitize.sanitize(req.query);
    }

    next();
});


// Serving static files
app.use('/public', express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(path.join(__dirname, '../public/uploads')));

// Routes
app.use(maintenanceMiddleware);
app.use('/api/v1', routes);

// 404 Handler - Catch-all for undefined routes
app.use((req, res, next) => {
    next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Global Error Handler
app.use(errorHandler);

module.exports = app;
