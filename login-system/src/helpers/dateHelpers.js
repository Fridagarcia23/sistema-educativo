// Archivo: src/helpers/dateHelpers.js

// Función para formatear una fecha
function formatDate(dateStr) {
    const date = new Date(dateStr);
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return date.toLocaleDateString('es-ES', options);
}

// Exportar la función para poder utilizarla en otros archivos
module.exports = {
    formatDate
};
