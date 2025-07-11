const app = require('./app.js');
const connectMongoDB = require('./dataBase/dataBase.mongo');

connectMongoDB();

const port = app.get('port');
app.listen(port, () => {
    console.log(`la aplicacion corre en el puerto: ${port}`);
});