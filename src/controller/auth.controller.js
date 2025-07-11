const bcrypt = require('bcrypt');
const db = require('../dataBase/dataBase.orm');  // Importas instancia y modelos
const UserPreferences = require('../model/userPreferences.model'); // Agrega esta línea

const User = db.users;  // Modelo ya definido y sincronizado
const Role = db.rol;

async function register(req, res) {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: 'Faltan datos requeridos' });
  }

  try {
    // Verificar si el email ya existe
    const existingUser = await User.findOne({ where: { emailUser: email } });
    if (existingUser) {
      return res.status(400).json({ message: 'Email ya registrado' });
    }

    // Buscar el rol en la tabla roles
    const foundRole = await Role.findOne({ where: { nameRole: role } });
    if (!foundRole) {
      return res.status(400).json({ message: 'Rol no válido' });
    }

    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear usuario con idRole asignado
    await User.create({
      nameUser: name,
      emailUser: email,
      passwordUser: hashedPassword,
      stateUser: 'active',
      idRole: foundRole.idRoles,
    });

    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
}

async function login(req, res) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Faltan datos requeridos' });
  }

  try {
    // Busca el usuario por email
    const user = await User.findOne({ where: { emailUser: email } });
    if (!user) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    // Compara la contraseña
    const validPassword = await bcrypt.compare(password, user.passwordUser);
    if (!validPassword) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    // Busca el rol del usuario
    const role = await Role.findOne({ where: { idRoles: user.idRole } });

    // Guarda el usuario en la sesión
    req.session.user = {
      id: user.idUsers,
      name: user.nameUser,
      email: user.emailUser,
      role: role ? role.nameRole : 'user'
    };

    // Devuelve el usuario y rol
    res.json({
      message: 'Login exitoso',
      user: req.session.user
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
}

// Guardar o actualizar preferencias de usuario
async function savePreferences(req, res) {
  try {
    const { theme, font, mainColor } = req.body;
    const user = req.session.user;

    if (!user) {
      return res.status(401).json({ message: 'No autenticado' });
    }

    // Incluye los campos requeridos por el esquema de MongoDB
    const prefs = await UserPreferences.findOneAndUpdate(
      { userId: user.id },
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        name: user.name,
        theme,
        font,
        mainColor
      },
      { new: true, upsert: true }
    );

    res.json({ message: 'Preferencias guardadas', preferences: prefs });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al guardar preferencias' });
  }
}

// Obtener preferencias de usuario
async function getPreferences(req, res) {
  try {
    const user = req.session.user;
    if (!user) return res.status(401).json({ message: 'No autenticado' });
    const prefs = await UserPreferences.findOne({ userId: user.id });
    res.json({ preferences: prefs });
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener preferencias' });
  }
}

// Obtener perfil de usuario
async function getProfile(req, res) {
  const user = req.session.user;
  if (!user) return res.status(401).json({ message: 'No autenticado' });
  res.json({ user });
}

// Actualizar perfil de usuario
async function updateProfile(req, res) {
  try {
    const user = req.session.user;
    if (!user) return res.status(401).json({ message: 'No autenticado' });

    const { email, name, role, password } = req.body;
    const updates = {};

    if (email) updates.emailUser = email;
    if (name) updates.nameUser = name;

    // Si se envía un nombre de rol, busca el idRole correspondiente
    if (role) {
      let idRole = role;
      if (isNaN(role)) {
        // Buscar el idRole por nombre
        const foundRole = await Role.findOne({ where: { nameRole: role } });
        if (!foundRole) {
          return res.status(400).json({ message: 'Rol no válido' });
        }
        idRole = foundRole.idRoles;
      }
      updates.idRole = idRole;
    }

    if (password && password.trim() !== '') {
      updates.passwordUser = await bcrypt.hash(password, 10);
    }

    // Busca y actualiza el usuario en MySQL usando el id correcto de sesión
    const dbUser = await User.findByPk(user.id);
    if (!dbUser) return res.status(404).json({ message: 'Usuario no encontrado' });

    await dbUser.update(updates);

    // Actualiza la sesión
    req.session.user = {
      ...user,
      email: updates.emailUser || user.emailUser,
      name: updates.nameUser || user.nameUser,
      role: updates.idRole || user.idRole
    };

    res.json({ message: 'Perfil actualizado', user: req.session.user });
  } catch (error) {
    console.error('Error al actualizar perfil:', error);
    res.status(500).json({ message: 'Error al actualizar perfil', error: error.message });
  }
}

module.exports = { register, login, savePreferences, getPreferences, getProfile, updateProfile };
