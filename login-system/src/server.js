const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mysql = require('mysql');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcrypt');
const cors = require('cors');
const saltRounds = 10; // Número de rondas de sal para hashing
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const estudiantesRouter = require('./routes/usuarios');
const router = express.Router();  
const Pagination = require('pagination');

const methodOverride = require('method-override');

const app = express();
const port = process.env.PORT || 3000;

// Configurar CORS
app.use(cors());

// Conexión a la base de datos MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'datos_alumnos',
  port: 3307
});

// Exportar la conexión de la base de datos para usarla en otros archivos
module.exports = db;

app.use(session({
  secret: 'tu_secreto_fuerte', // Cambia esto por una cadena secreta fuerte
  resave: false, // No resave la sesión si no ha sido modificada
  saveUninitialized: false, // No guarda sesiones no inicializadas
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // Establece la duración de la cookie (1 día en este caso)
    secure: false, // Cambia a true si usas HTTPS
    httpOnly: true // Previene el acceso a la cookie desde JavaScript del lado del cliente
  }
}));

const profileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public', 'uploads', 'perfiles'));
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Guardar con un nombre único
  }
});

const uploadProfile = multer({ storage: profileStorage });

app.post('/uploadProfile', uploadProfile.single('image'), (req, res) => {
  const userId = req.session.user.id_usuario; // Obtener el ID del usuario de la sesión
  const nombre = req.body.name;
  const imagePath = `/uploads/perfiles/${req.file.filename}`; // Ruta de la imagen subida

  const query = 'UPDATE usuarios SET nombre_usuario = ?, foto = ? WHERE id_usuario = ?';
  db.query(query, [nombre, imagePath, userId], (err, result) => {
    if (err) {
      console.error('Error al actualizar la foto de perfil:', err);
      return res.status(500).send({ success: false, message: 'Error en el servidor' });
    }

    // Actualizar la sesión con la nueva foto
    req.session.user.profilePicture = imagePath;

    res.send({ success: true, message: 'Foto de perfil actualizada exitosamente', imagePath });
  });
});

// Configuración de Multer para almacenamiento de archivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, path.join(__dirname, 'public', 'uploads'));
  },
  filename: (req, file, cb) => {
      cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

// Middleware para manejar las peticiones POST
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.post('/upload', upload.single('image'), (req, res) => {
  if (req.file) {
      res.redirect('/album'); // Redirige a /album después de subir el archivo
  } else {
      res.status(400).send('No se ha subido ningún archivo');
  }
});

// Ruta principal
app.get('/', (req, res) => {
  res.send('Página principal');
});


app.get('/album', (req, res) => {
  fs.readdir(path.join(__dirname, 'public', 'uploads'), (err, files) => {
      if (err) {
          console.error('Error al leer el directorio de imágenes:', err);
          res.status(500).send('Error al obtener las imágenes');
          return;
      }
      // Filtrar solo archivos de imagen
      const images = files.filter(file => ['.jpg', '.jpeg', '.png'].includes(path.extname(file).toLowerCase()));
      res.render('album', { images });
  });
});

app.use((err, req, res, next) => {
  if (err) {
    return res.status(500).send('Error al subir el archivo: ' + err.message);
  }
  next();
});

app.use(methodOverride('_method'));
db.connect((err) => {
  if (err) throw err;
  console.log('Conectado a la base de datos MySQL');
});

app.use(bodyParser.urlencoded({ extended: true }));

function formatDate(dateStr) {
  const date = new Date(dateStr);
  const options = { year: 'numeric', month: 'long', day: 'numeric' };
  return date.toLocaleDateString('es-ES', options);
}

// Configuración de body-parser para manejar datos POST
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


// Configuración de las rutas estáticas y vistas
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');


// Servir la vista principal
app.get('/usuarios', (req, res) => {
  res.render('usuarios/index');
});


app.post('/login', (req, res) => {
  const { email, contraseña } = req.body;

  // Verificación de campos vacíos
  if (!email || !contraseña) {
    req.session.error = 'Todos los campos son requeridos';
    return res.redirect('/login');
  }

  const query = 'SELECT id_usuario, nombre_usuario, contraseña, id_rol, foto FROM usuarios WHERE email = ? AND estado = \'activo\'';
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error('Error en la consulta de usuario:', err);
      req.session.error = 'Error en el servidor';
      return res.redirect('/login');
    }

    if (results.length === 0) {
      req.session.error = 'Email, contraseña incorrectos o usuario inactivo';
      return res.redirect('/login');
    }

    const usuario = results[0];

    // Comparación de contraseña
    bcrypt.compare(contraseña, usuario.contraseña, (err, result) => {
      if (err) {
        console.error('Error al comparar la contraseña:', err);
        req.session.error = 'Error en el servidor';
        return res.redirect('/login');
      }

      if (!result) {
        req.session.error = 'Email o contraseña incorrectos';
        return res.redirect('/login');
      }

      // Obtener nombre del rol
      const getRoleNameQuery = 'SELECT nombre_rol FROM roles WHERE id_rol = ?';
      db.query(getRoleNameQuery, [usuario.id_rol], (err, roleResult) => {
        if (err) {
          console.error('Error al obtener el nombre del rol:', err);
          req.session.error = 'Error en el servidor';
          return res.redirect('/login');
        }

        req.session.user = {
          id_usuario: usuario.id_usuario,
          nombre_usuario: usuario.nombre_usuario,
          rol: roleResult[0].nombre_rol,
          profilePicture: usuario.foto || '/path/to/default/profile.jpg' // Cambia esta ruta
        };

        req.session.success = 'Bienvenido, has iniciado sesión exitosamente';
        res.redirect('/dashboard'); // Asegúrate de que esta ruta esté correcta
      });
    });
  });
});



// En la vista de login
app.get('/login', (req, res) => {
  const error = req.session.error;
  delete req.session.error;
  res.render('login', { error });
});

// Ruta GET para mostrar el formulario de login de profesor
app.get('/login-profesor', (req, res) => {
  const error = req.session.error;
  delete req.session.error; // Elimina el error de la sesión después de mostrarlo
  res.render('profesores/login-profesor', { error }); // Pasar el error a la vista
});


// En la vista del dashboard
app.get('/dashboard', (req, res) => {
  const success = req.session.success;
  delete req.session.success;
  res.render('dashboard', { success, user: req.session.user });
});


// Ruta para mostrar el dashboard de profesor
app.get('/dashboard-profesor', (req, res) => {
  // Verifica si el usuario está autenticado
  if (!req.session.user) {
    return res.redirect('/login-profesor'); // Redirige al login si no está autenticado
  }

  // Renderiza la vista del dashboard de profesor
  res.render('dashboard-profesor', { user: req.session.user });
});

// Ruta para el login de profesor
// Ruta para el login de profesor
app.post('/login-profesor', (req, res) => {
  const { email, contraseña } = req.body;

  // Verificación de campos vacíos
  if (!email || !contraseña) {
    req.session.error = 'Todos los campos son requeridos';
    return res.redirect('/login-profesor');
  }

  const query = 'SELECT id_usuario, nombre_usuario, contraseña, id_rol, foto FROM usuarios WHERE email = ? AND estado = \'activo\'';
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error('Error en la consulta de usuario:', err);
      req.session.error = 'Error en el servidor';
      return res.redirect('/login-profesor');
    }

    if (results.length === 0) {
      req.session.error = 'Email, contraseña incorrectos o usuario inactivo';
      return res.redirect('/login-profesor');
    }

    const usuario = results[0];

    // Comparación de contraseña
    bcrypt.compare(contraseña, usuario.contraseña, (err, result) => {
      if (err) {
        console.error('Error al comparar la contraseña:', err);
        req.session.error = 'Error en el servidor';
        return res.redirect('/login-profesor');
      }

      if (!result) {
        req.session.error = 'Email o contraseña incorrectos';
        return res.redirect('/login-profesor');
      }

      // Obtener el nombre del rol
      const getRoleNameQuery = 'SELECT nombre_rol FROM roles WHERE id_rol = ?';
      db.query(getRoleNameQuery, [usuario.id_rol], (err, roleResult) => {
        if (err) {
          console.error('Error al obtener el nombre del rol:', err);
          req.session.error = 'Error en el servidor';
          return res.redirect('/login-profesor');
        }

        req.session.user = {
          id_usuario: usuario.id_usuario,
          nombre_usuario: usuario.nombre_usuario,
          rol: roleResult[0].nombre_rol,
          profilePicture: usuario.foto || '/path/to/default/profile.jpg' // Cambia esta ruta
        };

        req.session.success = 'Bienvenido, has iniciado sesión exitosamente';
        res.redirect('/dashboard-profesor'); // Asegúrate de que esta ruta esté correcta
      });
    });
  });
});


// módulo usuarios
// Ruta para obtener usuarios con paginación
app.get('/api/usuarios', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const offset = (page - 1) * limit;

  const query = `SELECT * FROM usuarios LIMIT ? OFFSET ?`;
  db.query(query, [limit, offset], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      // Contar el total de usuarios para paginación
      db.query('SELECT COUNT(*) AS count FROM usuarios', (err, countResult) => {
          if (err) return res.status(500).json({ error: err.message });

          res.json({
              users: results,
              totalPages: Math.ceil(countResult[0].count / limit)
          });
      });
  });
});

// Ruta para obtener un usuario específico
app.get('/api/usuarios/:id', (req, res) => {
  const userId = req.params.id;
  const query = 'SELECT * FROM usuarios WHERE id_usuario = ?';
  db.query(query, [userId], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      if (results.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

      res.json(results[0]);
  });
});

// Ruta para crear usuario y profesor
app.post('/api/usuarios', (req, res) => {
  const { nombre_usuario, email, contraseña, telefono, direccion, fecha_nacimiento, genero, estado, id_rol, especialidad, experiencia_years } = req.body;
  const hashedPassword = bcrypt.hashSync(contraseña, 10); // Hash de la contraseña
  
  const sqlUsuario = `INSERT INTO usuarios (nombre_usuario, email, contraseña, telefono, direccion, fecha_nacimiento, genero, estado, id_rol) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
  db.query(sqlUsuario, [nombre_usuario, email, hashedPassword, telefono, direccion, fecha_nacimiento, genero, estado, id_rol], (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      const userId = result.insertId; // Obtener el ID del nuevo usuario

      // Insertar en la tabla profesores
      const sqlProfesor = `INSERT INTO profesores (id_profesor, nombre, email, especialidad, experiencia_years, fecha_ingreso) VALUES (?, ?, ?, ?, ?, ?)`;
      db.query(sqlProfesor, [userId, nombre_usuario, email, especialidad, experiencia_years, new Date()], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.status(201).json({ message: 'Usuario y profesor creados exitosamente' });
      });
  });
});

// Ruta para actualizar usuario y profesor
app.put('/api/usuarios/:id', (req, res) => {
  const id = req.params.id;
  const { nombre_usuario, email, contraseña, telefono, direccion, fecha_nacimiento, genero, estado, id_rol, especialidad, experiencia_years } = req.body;
  const hashedPassword = contraseña ? bcrypt.hashSync(contraseña, 10) : null;

  // Actualizar en la tabla usuarios
  let sqlUsuario = `UPDATE usuarios SET nombre_usuario = ?, email = ?, telefono = ?, direccion = ?, fecha_nacimiento = ?, genero = ?, estado = ?, id_rol = ?`;
  const updatesUsuario = [nombre_usuario, email, telefono, direccion, fecha_nacimiento, genero, estado, id_rol];

  if (hashedPassword) {
      sqlUsuario += ', contraseña = ?';
      updatesUsuario.push(hashedPassword);
  }
  
  sqlUsuario += ' WHERE id_usuario = ?';
  updatesUsuario.push(id);

  db.query(sqlUsuario, updatesUsuario, (err) => {
      if (err) return res.status(500).json({ error: err.message });

      // Actualizar en la tabla profesores
      const sqlProfesor = `UPDATE profesores SET nombre = ?, email = ?, especialidad = ?, experiencia_years = ? WHERE id_profesor = ?`;
      db.query(sqlProfesor, [nombre_usuario, email, especialidad, experiencia_years, id], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: 'Usuario y profesor actualizados exitosamente' });
      });
  });
});

// Ruta para eliminar usuario
app.delete('/api/usuarios/:id', (req, res) => {
  const id = req.params.id;

  // Primero eliminar de la tabla profesores
  const sqlProfesor = 'DELETE FROM profesores WHERE id_profesor = ?';
  db.query(sqlProfesor, [id], (err) => {
      if (err) return res.status(500).json({ error: err.message });

      // Luego eliminar de la tabla usuarios
      const sqlUsuario = 'DELETE FROM usuarios WHERE id_usuario = ?';
      db.query(sqlUsuario, [id], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: 'Usuario y profesor eliminados exitosamente' });
      });
  });
});

// Configuración de la carpeta de uploads
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

//modulo de grados
// Ruta para obtener todos los grados
app.get('/api/grados', (req, res) => {
  db.query('SELECT * FROM grados', (err, grados) => {
      if (err) {
          console.error('Error al obtener grados:', err);
          return res.status(500).json({ success: false });
      }

      const gradoPromises = grados.map(grado =>
          new Promise((resolve, reject) => {
              db.query('SELECT nombre_seccion FROM secciones WHERE id_grado = ?', [grado.id_grado], (err, secciones) => {
                  if (err) {
                      reject(err);
                  } else {
                      grado.secciones = secciones.map(seccion => seccion.nombre_seccion).join(', ');
                      resolve(grado);
                  }
              });
          })
      );

      Promise.all(gradoPromises)
          .then(result => res.json(result))
          .catch(err => {
              console.error('Error al obtener secciones:', err);
              res.status(500).json({ success: false });
          });
  });
});

// Ruta para obtener un grado específico por ID
app.get('/api/grados/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM grados WHERE id_grado = ?', [id], (err, grados) => {
      if (err) {
          console.error('Error al obtener grado:', err);
          return res.status(500).json({ success: false });
      }

      if (grados.length === 0) {
          return res.status(404).json({ success: false, message: 'Grado no encontrado' });
      }

      const grado = grados[0];

      db.query('SELECT nombre_seccion FROM secciones WHERE id_grado = ?', [id], (err, secciones) => {
          if (err) {
              console.error('Error al obtener secciones:', err);
              return res.status(500).json({ success: false });
          }

          grado.secciones = secciones.map(seccion => seccion.nombre_seccion).join(', ');
          res.json(grado);
      });
  });
});



// Crear grado
app.post('/api/grados/create', (req, res) => {
  const { nombre_grado, nivel_academico, secciones } = req.body;

  db.query('INSERT INTO grados (nombre_grado, nivel_academico) VALUES (?, ?)', 
      [nombre_grado, nivel_academico], 
      (err, result) => {
          if (err) {
              console.error('Error al insertar el grado:', err);
              return res.status(500).json({ success: false });
          }

          const id_grado = result.insertId;

          let seccionesArray = [];
          if (Array.isArray(secciones)) {
              seccionesArray = secciones;
          } else if (typeof secciones === 'string') {
              seccionesArray = secciones.split(',').map(s => s.trim());
          }

          if (seccionesArray.length > 0) {
              const sectionQueries = seccionesArray.map(seccion => 
                  new Promise((resolve, reject) => {
                      db.query('INSERT INTO secciones (id_grado, nombre_seccion) VALUES (?, ?)', 
                          [id_grado, seccion], 
                          (err) => {
                              if (err) {
                                  reject(err);
                              } else {
                                  resolve();
                              }
                          }
                      );
                  })
              );

              Promise.all(sectionQueries)
                  .then(() => res.json({ success: true }))
                  .catch(err => {
                      console.error('Error al insertar secciones:', err);
                      res.status(500).json({ success: false });
                  });
          } else {
              res.json({ success: true });
          }
      }
  );
});

// Actualizar grado
app.post('/api/grados/update', (req, res) => {
  const { id_grado, nombre_grado, nivel_academico, secciones } = req.body;

  db.query('UPDATE grados SET nombre_grado = ?, nivel_academico = ? WHERE id_grado = ?', 
      [nombre_grado, nivel_academico, id_grado], 
      (err) => {
          if (err) {
              console.error('Error al actualizar el grado:', err);
              return res.status(500).json({ success: false });
          }

          db.query('DELETE FROM secciones WHERE id_grado = ?', [id_grado], (err) => {
              if (err) {
                  console.error('Error al eliminar secciones:', err);
                  return res.status(500).json({ success: false });
              }

              let seccionesArray = [];
              if (typeof secciones === 'string') {
                  seccionesArray = secciones.split(',').map(s => s.trim());
              } else if (Array.isArray(secciones)) {
                  seccionesArray = secciones;
              }

              if (seccionesArray.length > 0) {
                  const sectionQueries = seccionesArray.map(seccion => 
                      new Promise((resolve, reject) => {
                          db.query('INSERT INTO secciones (id_grado, nombre_seccion) VALUES (?, ?)', 
                              [id_grado, seccion], 
                              (err) => {
                                  if (err) {
                                      reject(err);
                                  } else {
                                      resolve();
                                  }
                              }
                          );
                      })
                  );

                  Promise.all(sectionQueries)
                      .then(() => res.json({ success: true }))
                      .catch(err => {
                          console.error('Error al insertar secciones:', err);
                          res.status(500).json({ success: false });
                      });
              } else {
                  res.json({ success: true });
              }
          });
      }
  );
});

// Eliminar grado
app.post('/api/grados/delete', (req, res) => {
  const { id_grado } = req.body;

  db.query('DELETE FROM grados WHERE id_grado = ?', [id_grado], (err) => {
      if (err) {
          console.error('Error al eliminar el grado:', err);
          return res.status(500).json({ success: false });
      }

      db.query('DELETE FROM secciones WHERE id_grado = ?', [id_grado], (err) => {
          if (err) {
              console.error('Error al eliminar secciones:', err);
              return res.status(500).json({ success: false });
          }
          res.json({ success: true });
      });
  });
});

//modulo alumnos
// Ruta para obtener todos los estudiantes con grados, secciones y año escolar
app.get('/api/estudiantes', (req, res) => {
  const query = `
    SELECT 
      e.id_estudiante,
      e.nombre,
      e.email,
      e.fecha_nacimiento,
      e.direccion,
      e.telefono,
      g.nombre_grado,
      s.nombre_seccion,
      eg.anio_escolar
    FROM estudiantes e
    JOIN estudiantes_grados eg ON e.id_estudiante = eg.id_estudiante
    JOIN grados g ON eg.id_grado = g.id_grado
    JOIN secciones s ON eg.id_seccion = s.id_seccion
    ORDER BY e.id_estudiante ASC;  -- Agregar ORDER BY aquí
  `;

  db.query(query, (err, estudiantes) => {
    if (err) {
      console.error('Error al obtener estudiantes:', err);
      return res.status(500).json({ success: false });
    }
    res.json(estudiantes);
  });
});

// Ruta para obtener un estudiante específico por ID
app.get('/api/estudiantes/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM estudiantes WHERE id_estudiante = ?', [id], (err, estudiantes) => {
    if (err) {
      console.error('Error al obtener estudiante:', err);
      return res.status(500).json({ success: false });
    }

    if (estudiantes.length === 0) {
      return res.status(404).json({ success: false, message: 'Estudiante no encontrado' });
    }

    res.json(estudiantes[0]);
  });
});

// Crear estudiante
// Ruta para agregar un estudiante
app.post('/estudiantes', (req, res) => {
  const { nombre, email, fecha_nacimiento, direccion, telefono, grado, seccion_modal, anio_escolar } = req.body;

  // Verifica los datos recibidos
  console.log('Datos recibidos:', { nombre, email, fecha_nacimiento, direccion, telefono, grado, seccion_modal, anio_escolar });

  // Primero, inserta el estudiante en la tabla 'estudiantes'
  const queryEstudiantes = `INSERT INTO estudiantes (nombre, email, fecha_nacimiento, direccion, telefono) VALUES (?, ?, ?, ?, ?)`;

  db.query(queryEstudiantes, [nombre, email, fecha_nacimiento, direccion, telefono], (error, results) => {
    if (error) {
      console.error('Error al insertar el estudiante:', error);
      return res.status(500).send('Error al insertar el estudiante');
    }

    // Obtén el ID del estudiante recién insertado
    const id_estudiante = results.insertId;

    // Luego, inserta los datos en la tabla 'estudiantes_grados'
    const queryEstudiantesGrados = `INSERT INTO estudiantes_grados (id_estudiante, id_grado, id_seccion, anio_escolar) VALUES (?, ?, ?, ?)`;

    db.query(queryEstudiantesGrados, [id_estudiante, grado, seccion_modal, anio_escolar], (error) => {
      if (error) {
        console.error('Error al insertar en estudiantes_grados:', error);
        return res.status(500).send('Error al insertar en estudiantes_grados');
      }

      // Envía una respuesta adecuada
      res.json({ success: true, message: 'Estudiante agregado exitosamente' });
    });
  });
});

// Ruta para actualizar un estudiante
app.put('/api/estudiantes/:id', (req, res) => {
  const id_estudiante = req.params.id;
  const { nombre, email, fecha_nacimiento, direccion, telefono, grado, seccion, anio_escolar } = req.body;

  if (!nombre || !email || !fecha_nacimiento || !direccion || !telefono || !grado || !seccion || !anio_escolar) {
    console.log('Datos incompletos');
    return res.status(400).json({ success: false, message: 'Todos los campos son requeridos.' });
  }

  const query = `
    UPDATE estudiantes
    SET nombre = ?, email = ?, fecha_nacimiento = ?, direccion = ?, telefono = ?, grado = ?, seccion = ?, anio_escolar = ?
    WHERE id_estudiante = ?
  `;

  const values = [nombre, email, fecha_nacimiento, direccion, telefono, grado, seccion, anio_escolar, id_estudiante];

  db.query(query, values, (err, results) => {
    if (err) {
      console.error('Error al actualizar el estudiante:', err);
      return res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }

    if (results.affectedRows === 0) {
      console.log('Estudiante no encontrado');
      return res.status(404).json({ success: false, message: 'Estudiante no encontrado' });
    }

    console.log('Estudiante actualizado correctamente');
    res.json({ success: true, message: 'Estudiante actualizado correctamente.' });
  });
});

// Eliminar estudiante
app.post('/api/estudiantes/delete', (req, res) => {
  const { id_estudiante } = req.body;

  db.query('DELETE FROM estudiantes WHERE id_estudiante = ?', [id_estudiante], (err) => {
    if (err) {
      console.error('Error al eliminar el estudiante:', err);
      return res.status(500).json({ success: false });
    }

    res.json({ success: true });
  });
});

// API para Grados
// Ruta para obtener los grados
app.get('/api/grados', async (req, res) => {
  try {
    const [grados] = await db.query('SELECT * FROM grados');
    res.json(grados);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener los grados' });
  }
});

// Ruta para obtener secciones
app.get('/api/secciones', (req, res) => {
  const gradoId = req.query.grado;

  // Consulta para obtener secciones basadas en el grado
  const query = gradoId ? 'SELECT * FROM secciones WHERE id_grado = ?' : 'SELECT * FROM secciones';
  const params = gradoId ? [gradoId] : [];

  db.query(query, params, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'Error al obtener las secciones' });
    }
    res.json(results);
  });
});




// Ruta para mostrar la vista de alumnos
app.get('/alumnos', async (req, res) => {
  try {
    // Reemplaza esta línea con la lógica para obtener los estudiantes desde tu base de datos
    const estudiantes = await db.query('SELECT * FROM estudiantes');
    res.render('alumnos/index', { estudiantes });
  } catch (error) {
    console.error('Error al obtener estudiantes:', error);
    res.status(500).send('Error interno del servidor');
  }
});


// Rutas
const authRouter = require('./routes/auth');
const cursosRouter = require('./routes/cursos'); // Asegúrate de tener este require
app.use('/', authRouter);
app.use('/cursos', cursosRouter);


app.get('/roles', (req, res) => {
  res.render('roles');
});

// Ruta para profesor
app.get('/profesores', (req, res) => {
  res.render('profesores/index'); // Renderiza la vista basico.ejs en la carpeta grados
});

app.get('/grados', (req, res) => {
  res.render('grados/index');  // Asegúrate de usar 'grados/index' si la carpeta es 'grados'
});



app.get('/login-profesor', (req, res) => {
  res.render('profesores/login-profesor');
});

app.get('/cursos', (req, res) => {
  res.render('cursos', { userName: 'Nombre de Usuario' }); // Renderiza la vista cursos.ejs
});

app.get('/profesores', (req, res) => {
  res.render('profesores', { userName: 'Nombre de Usuario' }); // Renderiza la vista profesores.ejs
});

app.get('/reportes', (req, res) => {
  res.render('reportes', { userName: 'Nombre de Usuario' }); // Renderiza la vista reportes.ejs
});

app.get('/calificaciones', (req, res) => {
  res.render('calificaciones', { userName: 'Nombre de Usuario' }); // Renderiza la vista calificaciones.ejs
});

app.get('/recibos', (req, res) => {
  res.render('recibos', { userName: 'Nombre de Usuario' }); // Renderiza la vista recibos.ejs
});

app.get('/lista-recibos', (req, res) => {
  res.render('lista-recibos', { userName: 'Nombre de Usuario' }); // Renderiza la vista lista-recibos.ejs
});

app.get('/asistencia', (req, res) => {
  res.render('asistencia', { userName: 'Nombre de Usuario' }); // Renderiza la vista asistencia.ejs
});

app.get('/tareas', (req, res) => {
  res.render('tareas', { userName: 'Nombre de Usuario' }); // Renderiza la vista tareas.ejs
});

app.get('/comentarios', (req, res) => {
  res.render('comentarios', { userName: 'Nombre de Usuario' }); // Renderiza la vista comentarios.ejs
});

app.get('/logout', (req, res) => {
  // Código para cerrar sesión y redirigir al login, por ejemplo
  res.redirect('/login');
});

// Ruta para la portada
app.get('/principal', (req, res) => {
  res.render('principal'); // Renderiza principal.ejs
});

// Ruta para "/page"
app.get('/page', (req, res) => {
  res.render('page'); // Renderiza 'page.ejs' desde la carpeta 'views'
});

// Ruta para la página de contacto
app.get('/contacto', (req, res) => {
  res.render('contacto');
});

// Ruta para la página sobre nosotros
app.get('/sobre', (req, res) => {
  res.render('sobre');
});

// Ruta para el álbum de fotos
app.get('/album', (req, res) => {
  res.render('album'); // Renderiza el archivo album.ejs en la carpeta views
});

// Ruta para Preprimaria
app.get('/preprimaria', (req, res) => {
  res.render('preprimaria');
});

// Ruta para Primaria
app.get('/primaria', (req, res) => {
  res.render('primaria');
});

// Ruta para Básico
app.get('/basico', (req, res) => {
  res.render('basico');
});

// Ruta para Diversificado
app.get('/diversificado', (req, res) => {
  res.render('diversificado');
});

app.get('/usuarios', (req, res) => {
  res.render('usuarios/index'); // Renderiza solo el contenido del CRUD sin recargar toda la página
});


// Ruta para servir la nueva página principal
app.get('/home', (req, res) => {
  res.render('home');
});

// Ruta para el dashboard de administrador
app.get('/dashboard', (req, res) => {
  res.render('dashboard', { roleName: 'Administrador', userName: req.session.nombre });
});

// Ruta para el dashboard de profesor
app.get('/dashboard-profesor', (req, res) => {
  res.render('dashboard-profesor', { roleName: 'Profesor', userName: req.session.nombre });
});

// Configurar la ruta para la página de recuperación de contraseña del profesor
app.get('/reset-profesor', (req, res) => {
  res.render('reset-profesor'); // Renderiza el archivo reset-profesor.ejs
});

app.get('/usuarios', (req, res) => {
  const userId = req.session.user ? req.session.user.id_usuario : null; // Obtener el ID del usuario de la sesión

  if (!userId) {
    return res.redirect('/login'); // Redirige al usuario si no está autenticado
  }

  // Cambia a `id_usuario` en la consulta
  db.query('SELECT * FROM usuarios WHERE id_usuario = ?', [userId], (error, results) => {
    if (error) {
      console.error('Error en la consulta: ', error);
      return res.status(500).send('Error en el servidor');
    }

    if (results.length === 0) {
      return res.status(404).send('Usuario no encontrado');
    }

    const user = results[0];
    console.log('Usuario:', user); // Verifica el contenido de `user`
    
    // Asegúrate de pasar 'user' a la vista
    res.render('usuarios/index', { user });
  });
});


// Middleware para pasar la información del usuario a todas las vistas
app.use((req, res, next) => {
  if (req.session.user) {
    // Si hay un usuario logueado, pasamos sus datos a las vistas
    res.locals.user = req.session.user;
  } else {
    res.locals.user = null; // Si no hay sesión, pasamos null
  }
  next();
});



// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});