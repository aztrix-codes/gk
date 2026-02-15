const mysql = require('mysql2/promise');
require('dotenv').config();

const formatCaCert = (cert) => {
    if (!cert) return undefined;
    if (cert.includes('\n') && !cert.includes('\\n')) return cert;
    return cert.replace(/\\n/g, '\n');
};

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: parseInt(process.env.DB_PORT || '15620'),
    ssl: {
        ca: formatCaCert(process.env.DB_SSL_CA),
        rejectUnauthorized: false 
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 10000 
});

if (process.env.NODE_ENV !== 'production') {
    pool.getConnection()
        .then(conn => {
            console.log('✅ Local connection test successful');
            conn.release();
        })
        .catch(err => console.error('❌ Local connection test failed:', err.message));
}

module.exports = pool;