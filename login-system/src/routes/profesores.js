const express = require('express');
const router = express.Router();

// Ruta para la página de cursos
router.get('/', (req, res) => {
  res.render('profesores', { userName: 'Nombre de Usuario' }); // Renderiza la vista cursos.ejs
});

module.exports = router;
