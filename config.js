const config = {
    development: {
        port: process.env.PORT || 3000,
        mongoUri: 'mongodb://127.0.0.1:27017/harris_journal',
        baseUrl: 'http://localhost:3000',
        uploadDir: 'public/uploads'
    },
    production: {
        port: process.env.PORT || 3000,
        mongoUri: process.env.MONGODB_URI,
        baseUrl: process.env.BASE_URL,
        uploadDir: process.env.UPLOAD_DIR || 'public/uploads'
    }
};

module.exports = config[process.env.NODE_ENV || 'development']; 