// routes/reports.js
const express = require('express');
const router = express.Router();
router.get('/reportes', async (req, res) => {
    const { status, start_date, end_date } = req.query;
    
    // Construir consulta SQL basada en los filtros
    let query = 'SELECT * FROM usuarios WHERE 1=1';
    
    if (status === 'activos') {
        query += ' AND activo = 1';
    } else if (status === 'inactivos') {
        query += ' AND activo = 0';
    }
    
    if (start_date && end_date) {
        query += ` AND fecha_creacion BETWEEN '${start_date}' AND '${end_date}'`;
    } else if (start_date) {
        query += ` AND fecha_creacion >= '${start_date}'`;
    } else if (end_date) {
        query += ` AND fecha_creacion <= '${end_date}'`;
    }
    
    try {
        const [rows] = await db.execute(query);
        res.render('reportes', { usuarios: rows });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error al generar el reporte');
    }
});

module.exports = router;
