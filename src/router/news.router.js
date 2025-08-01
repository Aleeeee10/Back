// Router para el recurso: Noticias (News)
const express = require('express');
const router = express.Router();
const controller = require('../controller/news.controller');

router.get('/', controller.listar);
router.post('/', controller.crear);
router.put('/:id', controller.actualizar);
router.delete('/:id', controller.eliminar);

module.exports = router;
