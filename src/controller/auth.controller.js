const bcrypt = require('bcrypt');
const db = require('../dataBase/dataBase.orm');  // Importas instancia y modelos

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

module.exports = { register, login };
