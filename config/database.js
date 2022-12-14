const mongoose = require('mongoose');

// TODO: change DB according to assignment
const CONNECTION_STRING = 'mongodb://127.0.0.1:27017/scaffoldDb';

module.exports = async(app) => {
    try {
        await mongoose.connect((CONNECTION_STRING), {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log('Database is connected');

    } catch (error) {
        console.log(error.message);
        process.exit(1);
    }
};