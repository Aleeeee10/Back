// src/router/matches.router.js
// Router para el recurso: Partidos (Matches)
const express = require('express');
const router = express.Router();
const controller = require('../controller/matches.controller');

router.get('/', controller.listar);
router.post('/', controller.crear);
router.put('/:id', controller.actualizar);
router.delete('/:id', controller.eliminar);

module.exports = router;
