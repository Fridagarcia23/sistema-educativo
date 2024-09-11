const bcrypt = require('bcryptjs');

const passwords = ['Jaime2020$', 'hashed_password']; // Agrega aquí las contraseñas que necesitas hashear

passwords.forEach(password => {
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) throw err;
    console.log(`Contraseña: ${password}`);
    console.log(`Hash: ${hash}`);
  });
});
