const mongoose = require('mongoose');
const { MONGO_URI } = require('../keys');
const UserPreferences = require('../model/userPreferences.model'); // <-- IMPORTA TU MODELO

// Opciones de conexión recomendadas para Mongoose
const MONGODB_OPTIONS = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000, // 5 segundos para selección de servidor
  socketTimeoutMS: 45000, // 45 segundos para timeout de operaciones
  family: 4, // Usar IPv4
  maxPoolSize: 10, // Máximo de conexiones en el pool
  retryWrites: true,
  w: 'majority'
};

const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI, MONGODB_OPTIONS); // Cambia aquí
    console.log('MongoDB Connected...');
    // Crear la colección si no existe
    await UserPreferences.createCollection();
    console.log('Colección UserPreferences lista.');
  } catch (err) {
    console.error('MongoDB Connection Error:', err);
    process.exit(1);
  }
};

// Manejo de eventos de conexión
mongoose.connection.on('connected', () => {
  console.log('Mongoose connected to DB');
});

mongoose.connection.on('error', err => {
  console.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose disconnected');
});

// Manejo de cierre de aplicación
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  console.log('Mongoose connection closed due to app termination');
  process.exit(0);
});

module.exports = connectDB;