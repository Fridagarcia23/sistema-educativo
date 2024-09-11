const express = require('express');
const router = express.Router();

// Asegúrate de que estas rutas existen y están bien definidas
router.get('/', (req, res) => {
  res.send('Página de Usuarios'); // Cambia esto por la vista correcta
});

router.get('/nuevo', (req, res) => {
  res.send('Formulario de Nuevo Usuario'); // Cambia esto por la vista correcta
});

router.post('/nuevo', (req, res) => {
  // Lógica para agregar un nuevo usuario
});

router.get('/editar/:id', (req, res) => {
  res.send(`Formulario de Edición para Usuario ${req.params.id}`); // Cambia esto por la vista correcta
});

router.post('/editar/:id', (req, res) => {
  // Lógica para actualizar un usuario
});

router.post('/eliminar/:id', (req, res) => {
  // Lógica para eliminar un usuario
});

module.exports = router;
