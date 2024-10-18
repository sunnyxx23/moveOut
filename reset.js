const fs = require('fs');
const path = require('path');
const config = require('./db/config.json');
const bcrypt = require('bcrypt');
const mysql = require("promise-mysql");

const uploadsDir = './uploads';
let db;

(async function() {
    try {
        db = await mysql.createConnection(config);
        console.log('Database connected for routes');

        // Insert users after connecting to the database
        await insertUsers();

        // Close the database connection after the users are inserted
        await db.end();
        console.log('Database connection closed.');
        
    } catch (err) {
        console.error('Error connecting to the database:', err);
    }

    // Ensure the DB connection closes on process exit if not already done
    process.on('exit', async () => {
        if (db) await db.end();
    });
})();

// Function to recursively delete directory contents
function clearDirectory(dirPath) {
    if (fs.existsSync(dirPath)) {
        fs.readdirSync(dirPath).forEach((file) => {
            const currentPath = path.join(dirPath, file);
            if (fs.lstatSync(currentPath).isDirectory()) {
                // Recursively delete contents of subdirectory
                clearDirectory(currentPath);
                fs.rmdirSync(currentPath); // Remove the empty directory
            } else {
                fs.unlinkSync(currentPath); // Delete file
            }
        });
    }
}

clearDirectory(uploadsDir);

// Inserts users with hashed password to make testing easier
async function insertUsers() {
    const users = [
        { email: 'adm@email.com', password: 'Admin123!', verified: 1, isAdmin: 1, isDisabled: 0 },
        { email: 'user1@email.com', password: 'Test123!', verified: 1, isAdmin: 0, isDisabled: 0 },
        { email: 'user2@email.com', password: 'Test123!', verified: 1, isAdmin: 0, isDisabled: 0 },
        { email: 'user3@email.com', password: 'Test123!', verified: 1, isAdmin: 0, isDisabled: 1 },
        { email: 'user4@email.com', password: 'Test123!', verified: 0, isAdmin: 0, isDisabled: 0 },
        { email: 'user5@email.com', password: 'Test123!', verified: 0, isAdmin: 0, isDisabled: 0 },
    ];

    for (const user of users) {
        try {
            const hashedPassword = await bcrypt.hash(user.password, 10);
            const sql = `INSERT INTO user (email, pass, verified, lastLoggedIn, isAdmin, isDisabled)
                         VALUES (?, ?, ?, CURRENT_TIMESTAMP(), ?, ?);`;

            await db.query(sql, [user.email, hashedPassword, user.verified, user.isAdmin, user.isDisabled]);
        } catch (err) {
            console.error('Error inserting user:', err);
        }
    }

    console.log('Users have been inserted.');
}
