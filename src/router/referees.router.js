// src/router/referees.router.js
// Router para el recurso: Árbitros (Referees)
const express = require('express');
const router = express.Router();
const controller = require('../controller/referees.controller');

router.get('/', controller.listar);
router.post('/', controller.crear);
router.put('/:id', controller.actualizar);
router.delete('/:id', controller.eliminar);

module.exports = router;
