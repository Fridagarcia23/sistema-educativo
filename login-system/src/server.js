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
  secret: 'secret',
  resave: true,
  saveUninitialized: true
}));

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

// Middleware para manejar datos JSON y URL codificadas
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

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

  if (!email || !contraseña) {
    req.session.error = 'Todos los campos son requeridos';
    return res.redirect('/login');
  }

  const query = 'SELECT id_usuario, nombre_usuario, contraseña, id_rol FROM usuarios WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error('Error en la consulta de usuario:', err);
      req.session.error = 'Error en el servidor';
      return res.redirect('/login');
    }

    if (results.length === 0) {
      req.session.error = 'Email o contraseña incorrectos';
      return res.redirect('/login');
    }

    const usuario = results[0];

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

      // Obtener el nombre del rol basado en el id_rol del usuario
      const getRoleNameQuery = 'SELECT nombre_rol FROM roles WHERE id_rol = ?';
      db.query(getRoleNameQuery, [usuario.id_rol], (err, roleResult) => {
        if (err) {
          console.error('Error al obtener el nombre del rol:', err);
          req.session.error = 'Error en el servidor';
          return res.redirect('/login');
        }

        if (roleResult.length === 0) {
          req.session.error = 'Rol no encontrado';
          return res.redirect('/login');
        }

        req.session.user = {
          id_usuario: usuario.id_usuario,
          nombre_usuario: usuario.nombre_usuario,
          rol: roleResult[0].nombre_rol
        };

        req.session.success = 'Bienvenido, has iniciado sesión exitosamente';
        res.redirect('/dashboard');
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

// En la vista del dashboard
app.get('/dashboard', (req, res) => {
  const success = req.session.success;
  delete req.session.success;
  res.render('dashboard', { success, user: req.session.user });
});

// Ruta para mostrar el dashboard
app.get('/dashboard-profesor', (req, res) => {
  // Verifica si el usuario está autenticado
  if (!req.session.user) {
      return res.redirect('/login-profesor'); // Redirige al login si no está autenticado
  }

  // Renderiza la vista del dashboard
  res.render('dashboard-profesor', { user: req.session.user });
});
app.post('/login-profesor', (req, res) => {
  const { email, contraseña } = req.body;

  if (!email || !contraseña) {
    req.session.error = 'Todos los campos son requeridos';
    return res.redirect('/login-profesor');
  }

  const query = 'SELECT id_usuario, nombre_usuario, contraseña, id_rol FROM usuarios WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error('Error en la consulta de usuario:', err);
      req.session.error = 'Error en el servidor';
      return res.redirect('/login-profesor');
    }

    if (results.length === 0) {
      req.session.error = 'Email o contraseña incorrectos';
      return res.redirect('/login-profesor');
    }

    const usuario = results[0];

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

      // Obtener el nombre del rol basado en el id_rol del usuario
      const getRoleNameQuery = 'SELECT nombre_rol FROM roles WHERE id_rol = ?';
      db.query(getRoleNameQuery, [usuario.id_rol], (err, roleResult) => {
        if (err) {
          console.error('Error al obtener el nombre del rol:', err);
          req.session.error = 'Error en el servidor';
          return res.redirect('/login-profesor');
        }

        if (roleResult.length === 0) {
          req.session.error = 'Rol no encontrado';
          return res.redirect('/login-profesor');
        }

        req.session.user = {
          id_usuario: usuario.id_usuario,
          nombre_usuario: usuario.nombre_usuario,
          rol: roleResult[0].nombre_rol
        };

        req.session.success = 'Bienvenido, has iniciado sesión exitosamente';
        res.redirect('/dashboard-profesor'); // Redirige a la página de inicio para profesores
      });
    });
  });
});

// modulo usuarios
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

// Ruta para crear usuario
app.post('/api/usuarios', upload.single('foto'), (req, res) => {
  const { nombre_usuario, email, contraseña, telefono, direccion, fecha_nacimiento, genero, estado, id_rol } = req.body;
  const foto = req.file ? req.file.filename : null;
  const hashedPassword = bcrypt.hashSync(contraseña, 10); // Hash de la contraseña
  
  const sql = `INSERT INTO usuarios (nombre_usuario, email, contraseña, telefono, direccion, fecha_nacimiento, genero, estado, id_rol, foto) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
  db.query(sql, [nombre_usuario, email, hashedPassword, telefono, direccion, fecha_nacimiento, genero, estado, id_rol, foto], (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ message: 'Usuario creado exitosamente' });
  });
});

app.get('/api/usuarios', (req, res) => {
  const sql = 'SELECT * FROM usuarios';
  db.query(sql, (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
  });
});

// Ruta para actualizar usuario
app.put('/api/usuarios/:id', upload.single('foto'), (req, res) => {
  const id = req.params.id;
  const { nombre_usuario, email, contraseña, telefono, direccion, fecha_nacimiento, genero, estado, id_rol } = req.body;
  const foto = req.file ? req.file.filename : null;
  const hashedPassword = contraseña ? bcrypt.hashSync(contraseña, 10) : null;

  let sql = `UPDATE usuarios SET nombre_usuario = ?, email = ?, telefono = ?, direccion = ?, fecha_nacimiento = ?, genero = ?, estado = ?, id_rol = ?`;
  const updates = [nombre_usuario, email, telefono, direccion, fecha_nacimiento, genero, estado, id_rol];
  
  if (hashedPassword) {
      sql += ', contraseña = ?';
      updates.push(hashedPassword);
  }
  
  if (foto) {
      sql += ', foto = ?';
      updates.push(foto);
  }
  
  sql += ' WHERE id_usuario = ?';
  updates.push(id);

  db.query(sql, updates, (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Usuario actualizado exitosamente' });
  });
});

// Ruta para eliminar usuario
app.delete('/api/usuarios/:id', (req, res) => {
  const id = req.params.id;
  const sql = 'DELETE FROM usuarios WHERE id_usuario = ?';
  db.query(sql, [id], (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Usuario eliminado exitosamente' });
  });
});

// Configuración de la carpeta de uploads
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

//modulo de grados

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

        const id_grado = result.insertId; // Obtener el ID del nuevo grado

        // Verificar y convertir `secciones` a un array si es necesario
        let seccionesArray = [];
        if (Array.isArray(secciones)) {
            seccionesArray = secciones;
        } else if (typeof secciones === 'string') {
            seccionesArray = secciones.split(',').map(s => s.trim());
        }

        // Insertar secciones asociadas
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

          // Eliminar secciones antiguas y añadir nuevas
          db.query('DELETE FROM secciones WHERE id_grado = ?', [id_grado], (err) => {
              if (err) {
                  console.error('Error al eliminar secciones:', err);
                  return res.status(500).json({ success: false });
              }

              // Verifica si secciones está definido y es una cadena
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


// Módulo alumnos

// Ruta para obtener los datos de alumnos en formato JSON
app.get('/api/alumnos', (req, res) => {
  db.query('SELECT * FROM alumnos', (err, results) => {
      if (err) {
          console.error(err);
          res.status(500).send('Error al obtener los alumnos');
          return;
      }
      res.json(results); // Retorna los resultados como JSON
  });
});
// Agregar un nuevo alumno
// Agregar un nuevo alumno
app.post('/alumnos', (req, res) => {
  const { nombre, apellido, grado, email, seccion, estado } = req.body;
  db.query('INSERT INTO alumnos (nombre, apellido, grado, email, seccion, estado) VALUES (?, ?, ?, ?, ?, ?)', [nombre, apellido, grado, email, seccion, estado], (err, result) => {
      if (err) throw err;
      res.redirect('alumnos/index');
  });
});

// Ruta para obtener las secciones
app.get('/secciones', (req, res) => {
  db.query('SELECT id_seccion, nombre_seccion FROM secciones', (error, results) => {
      if (error) {
          return res.status(500).json({ error: 'Error al obtener secciones' });
      }
      res.json(results);
  });
});

// Editar un alumno
app.get('/alumnos/edit/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM alumnos WHERE id_alumno = ?', [id], (err, results) => {
      if (err) throw err;
      res.render('alumnos/edit', { alumno: results[0] }); // Asegúrate de que la vista sea correcta
  });
});

// Ruta para obtener los grados
app.get('/grados', (req, res) => {
  const query = 'SELECT * FROM grados';
  db.query(query, (err, results) => {
      if (err) {
          console.error(err);
          res.status(500).send('Error al obtener los grados');
          return;
      }
      res.json(results);
  });
});

// Actualizar un alumno
// Actualizar un alumno
app.put('/alumnos/:id', (req, res) => {
  const { id } = req.params;
  const { nombre, apellido, grado, email, seccion, estado, telefono, fecha_nacimiento } = req.body;

  db.query('UPDATE alumnos SET nombre = ?, apellido = ?, grado = ?, email = ?, seccion = ?, estado = ?, telefono = ?, fecha_nacimiento = ? WHERE id_alumno = ?', 
      [nombre, apellido, grado, email, seccion, estado, telefono, fecha_nacimiento, id], 
      (err, result) => {
          if (err) {
              console.error('Error al actualizar el alumno:', err);
              return res.status(500).send('Error al actualizar el alumno.');
          }
          res.json({ message: 'Alumno actualizado con éxito.' }); // Respuesta en JSON
      }
  );
});

// Eliminar un alumno
app.delete('/alumnos/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM alumnos WHERE id_alumno = ?', [id], (err, result) => {
      if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Error al eliminar el alumno' });
      }
      res.redirect('/alumnos');
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
app.use('/profesores', cursosRouter);

app.get('/roles', (req, res) => {
  res.render('roles');
});
// Ruta para profesor
app.get('/profesores', (req, res) => {
  res.render('profesores/index'); // Renderiza la vista basico.ejs en la carpeta grados
});

app.get('/usuarios', (req, res) => {
  res.render('usuarios/index'); // Solo renderiza el contenido del CRUD
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
  const userId = req.session.userId;

  if (!userId) {
    return res.redirect('/login'); // Redirige al usuario si no está autenticado
  }

  db.query('SELECT * FROM usuarios WHERE id = ?', [userId], (error, results) => {
    if (error) {
      console.error('Error en la consulta: ', error);
      return res.status(500).send('Error en el servidor');
    }

    if (results.length === 0) {
      return res.status(404).send('Usuario no encontrado');
    }

    const user = results[0];
    console.log('Usuario:', user); // Verifica el contenido de `user`
    res.render('usuarios/index', { user });
  });
});



// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});