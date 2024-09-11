const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const mysql = require('mysql');
const db = require('../server'); // Importa la conexión db desde server.js

const router = express.Router();

// Página de login
router.get('/login', (req, res) => {
  res.render('login');
});



router.get('/dashboard', (req, res) => {
  const userName = req.session.nombre; // Obtener el nombre del usuario de la sesión
  const roleName = req.session.role; // Obtener el rol del usuario de la sesión
  // Lógica para mostrar el dashboard
  res.render('dashboard', { userName, roleName });
});

// Página de inicio del dashboard de profesores
router.get('/dashboard-profesor', (req, res) => {
  // Renderizar la vista 'dashboard-profesores'
  res.render('dashboard-profesor', {
    roleName: req.session.role, // Puedes pasar el rol del usuario si es necesario
    userName: req.session.nombre // Puedes pasar el nombre del usuario si es necesario
  });
});

router.get('/estudiantes', (req, res) => {
  res.render('estudiantes');
});

// Página de recuperación de contraseña
router.get('/reset', (req, res) => {
  res.render('reset');
});

// Página para establecer nueva contraseña
router.get('/new_password', (req, res) => {
  const token = req.query.token;
  res.render('new_password', { token });
});

// Procesar login
router.post('/login', (req, res) => {
  const { email, password, role } = req.body;
  db.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, results) => {
    if (err) throw err;
    if (results.length === 1) {
      const user = results[0];
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch && user.rol === role) {
        req.session.loggedin = true;
        req.session.email = email;
        req.session.role = role; // Guardar el rol en la sesión
        req.session.nombre = user.nombre; // Guardar el nombre en la sesión
        if (role === 'administrador') {
          res.redirect('/dashboard');
        } else if (role === 'profesor') {
          res.redirect('/dashboard-profesor');
        } else {
          res.send('Role not recognized.');
        }
      } else {
        res.send('Incorrect email, password, or role');
      }
    } else {
      res.send('User not found');
    }
  });
});

// Procesar solicitud de recuperación de contraseña
router.post('/reset', (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(20).toString('hex');
  const expiration = new Date(Date.now() + 3600000); // 1 hour from now

  db.query('UPDATE usuarios SET recuperacion_token = ?, recuperacion_expiracion = ? WHERE email = ?', [token, expiration, email], (err, results) => {
    if (err) throw err;
    if (results.affectedRows) {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'youremail@gmail.com',
          pass: 'yourpassword'
        }
      });

      const mailOptions = {
        to: email,
        from: 'passwordreset@demo.com',
        subject: 'Password Reset',
        text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
        Please click on the following link, or paste this into your browser to complete the process:\n\n
        http://${req.headers.host}/new_password?token=${token}\n\n
        If you did not request this, please ignore this email and your password will remain unchanged.\n`
      };

      transporter.sendMail(mailOptions, err => {
        if (err) throw err;
        res.send('An e-mail has been sent to ' + email + ' with further instructions.');
      });
    } else {
      res.send('No account with that email address exists.');
    }
  });
});

// Procesar nueva contraseña
router.post('/new_password', async (req, res) => {
  const { token, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query('SELECT * FROM usuarios WHERE recuperacion_token = ? AND recuperacion_expiracion > NOW()', [token], (err, results) => {
    if (err) throw err;
    if (results.length) {
      const email = results[0].email;
      db.query('UPDATE usuarios SET password = ?, recuperacion_token = NULL, recuperacion_expiracion = NULL WHERE email = ?', [hashedPassword, email], (err, results) => {
        if (err) throw err;
        res.send('Password has been updated.');
      });
    } else {
      res.send('Password reset token is invalid or has expired.');
    }
  });
});

module.exports = router;
