"use strict";
const mysql         = require('promise-mysql');
const cron          = require('node-cron')
const fs            = require('fs');
const bcrypt        = require('bcrypt');
const validator     = require('validator');
const jwt           = require('jsonwebtoken');
const path          = require('path');
const nodemailer    = require('nodemailer');
const config        = require('../db/config.json');


let db;
/**
 * Main function.
 * @async
 * @returns void
 */
(async function initializeDB() {
        db = await mysql.createConnection(config);
        console.log('Database connected for functions');
})();

const generateToken = (email) => {
    const secret = 'secretkey';
    const expiresIn = '1d';
  
    const token = jwt.sign({ email }, secret, { expiresIn });
    return token;
};

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
};


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'moveoutnoreply@gmail.com',
      pass: 'hfre rakm gyke lkvf'
    }
});

transporter.verify((error, success) => {
    if (error) {
      console.log('Error setting up transporter', error);
    } else {
      console.log('Server is ready to send messages');
    }
});

const sendVerificationEmail = (email, token) => {
    const verificationLink = `http://localhost:3000/verify-email?token=${token}`;
    
    // Setup the email options
    const mailOptions = {
        from: 'moveoutnoreply@gmail.com',  // Sender address
        to: email,                     // Recipient address (user-provided)
        subject: 'Verify your email address',
        text: `Please verify your email address by clicking the following link: ${verificationLink}`,
        html: `<p>Please verify your email address by clicking the following link: <a href="${verificationLink}">Verify Email</a></p>`
    };
  
    // Send the email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending verification email:', error);
        } else {
            console.log('Verification email sent:', info.response);
        }
    });
};

const sendMarketingEmail = (email) => {
    const mailOptions = {
        from: 'moveoutnoreply@gmail.com',  // Sender address
        to: email,                         // Recipient email (user-provided)
        subject: 'Stay Connected with MoveOut!',
        text: 'Remember that you can share your labels with others! Explore more features now.',
        html: `<p>Remember that you can share your labels with others! <strong>Explore more features now.</strong></p>`
    };

    // Send the email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending marketing email:', error);
        } else {
            console.log('Marketing email sent:', info.response);
        }
    });
};

const sendDeleteConfirmationEmail = (email) => {
    const deleteLink = `http://localhost:3000/final-delete/${email}`;
    
    const mailOptions = {
        from: 'moveoutnoreply@gmail.com',
        to: email,
        subject: 'Confirm Account Deletion',
        text: `Are you sure you want to delete your account? Click the link below to confirm: ${deleteLink}`,
        html: `<p>Are you sure you want to delete your account?</p>
               <p>Click the link below to confirm:</p>
               <a href="${deleteLink}">Delete Account</a>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending delete confirmation email:', error);
        } else {
            console.log('Delete confirmation email sent:', info.response);
        }
    });
};

// Middleware to check if we have a user, for protecting routes
async function checkUser(req, res, next) {
    const token = req.cookies.jwt;
    let sql = `CALL findByEmail(?);`;

    if (token) {
        jwt.verify(token, 'secretkey', async (err, decodedToken) => {
            if (err) {
                console.log(err);
                res.locals.user = null;
                res.locals.admin = false; // Set admin to false if there's an error
                next();
            } else {
                try {
                    let [user] = await db.query(sql, [decodedToken.email]);
                    if (user.length > 0) {
                        res.locals.user = user[0];
                        res.locals.admin = user[0].isAdmin === 1; // Match casing exactly
                    } else {
                        res.locals.user = null;
                        res.locals.admin = false; // Set admin to false if no user found
                    }
                } catch (dbErr) {
                    console.error("Database error:", dbErr);
                    res.locals.user = null;
                    res.locals.admin = false; // Set admin to false in case of a database error
                }
                next();
            }
        });
    } else {
        res.locals.user = null;
        res.locals.admin = false; // Set admin to false if no token
        next();
    }
};

// Login
async function login(req, res, email, password) {
    const sql = `CALL user_login(?, ?);`;
    const sqlUpdateLoginTime = `UPDATE user SET lastLoggedIn = CURRENT_TIMESTAMP WHERE email = ?;`;
    console.log(email, password);
    const hashpass = await bcrypt.hash(password, 10);
    const valid = await validateInput2(email, password);

    if (valid === true) {
            const token = generateToken(email);
            res.cookie('jwt', token, { httpOnly: true, maxAge: 86400 * 1000 });
            await db.query(sql, [email, hashpass]);
            await db.query(sqlUpdateLoginTime, [email]);
            return { success: true, errorMessage: null };
        } else {
            return { success: false, errorMessage: 'Invalid credentials' };
        }
};

// Signup
async function signup(req, res, email, password) {
    console.log(email, password);
    try {
        const sqlSignup = `CALL signup(?, ?, ?);`;
        const {valid, emailErrors, passwordErrors}  = await validateInput(email, password);
        
        if (!valid) {
            return {
                success: valid, 
                emailErrors: emailErrors.join(', '),
                passwordErrors: passwordErrors.join(', ')
            };
        };
        
        const hashpass = await bcrypt.hash(password, 10);
        const isGmail = email.endsWith('@gmail.com');
        const token = generateToken(email);

        if (isGmail) {
            let verified = 1
            await db.query(sqlSignup, [email, hashpass, verified]);
            res.cookie('jwt', token, {httpOnly: true });
            return { success: true, message: 'Account created successfully!' };
        } else {
            sendVerificationEmail(email, token);
            const verified = 0;
            await db.query(sqlSignup, [email, hashpass, verified]);
            return { success: true, message: 'Verify your email to login!' };
        }
    } catch (err) {
        console.error('Error during signup:', err);
        return { success: false, message: 'An error occurred during signup.' };
    }
};

// Checks all
const validateInput = async (email, password) => {
    let emailErrors = [];
    let passwordErrors = [];
    let valid = true;
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const checkEmailSql = `SELECT * FROM user WHERE email = ?`;
    const existingEmails = await db.query(checkEmailSql, [email]);

    if (!validator.isEmail(email)) {
        emailErrors.push(`That email is not a valid email`);
        valid = false;
    };

    if (Array.isArray(existingEmails) && existingEmails.length > 0) {
        emailErrors.push('That email is already registered');
        valid = false;
    };

    if (password.length < minLength) {
        passwordErrors.push('Password must be at least 8 characters long');
        valid = false;
    }; 
        
    if (!hasUpperCase || !hasLowerCase) {
        passwordErrors.push('Password must contain 1 lower- and 1 uppercase letter');
        valid = false;
    }
    return { valid, emailErrors, passwordErrors };
};

// Only checks password
const validateInput2 = async (email, password) => {
    let valid = true;
    const sql = `SELECT pass FROM user WHERE email = ? AND isDisabled = 0;`;
    const rows = await db.query(sql, [email]);
    if (rows.length > 0) {
        const user = rows[0];
        const auth = await bcrypt.compare(password, user.pass);
        if (auth) {
            return valid;
        }
    } else {
        valid = false;
        return valid ;
    }
};


async function getUsers(req, res) {
    const sql = `
    SELECT 
      u.email, 
      DATE_FORMAT(u.LastLoggedIn, '%Y-%m-%d %H:%i:%s') AS LastLoggedIn, 
      u.verified, 
      u.isAdmin, 
      u.isDisabled, 
      COUNT(b.id) AS totalBoxes
    FROM 
      user u
    LEFT JOIN 
      boxes b 
    ON 
      u.email = b.box_owner
    GROUP BY 
      u.email, u.LastLoggedIn, u.verified, u.isAdmin, u.isDisabled;
  `;
  
      try {
        const users = await db.query(sql); // Destructure to get rows
        console.log(users);
        return users;
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).send('Internal Server Error');
    }
};

async function verify(req, res, token, secret) {
    const decoded = jwt.verify(token, secret);
    let email = decoded.email;
    let sql = `UPDATE user SET verified = 1 WHERE email = ?;`;    
    db.query(sql, [email]);
};

async function deleteUser(req, res, email) {
    console.log(email);

    const boxDelete = `DELETE FROM boxes WHERE box_owner = ?;`;
    const userDelete = `DELETE FROM user WHERE email = ?;`;

    try {
        // Delete boxes from the database
        await db.query(boxDelete, [email]);

        // Clear the user's box directories from the file system
        const userBoxDirectory = path.join(__dirname, '../uploads', email); // Modify as needed
        console.log(userBoxDirectory);
        
        // Check if the directory exists and is not empty
        if (fs.existsSync(userBoxDirectory)) {
            if (fs.readdirSync(userBoxDirectory).length > 0) {
                clearDirectory(userBoxDirectory);
            }

            // Remove the root directory for the user if it exists (even if empty)
            fs.rmdirSync(userBoxDirectory);
        } else {
            console.log('Directory does not exist or has already been deleted.');
        }

        // Delete the user from the database
        await db.query(userDelete, [email]);

        console.log('User and boxes successfully deleted.');
        return;
    } catch (err) {
        console.error('Error deleting user and boxes:', err);
        res.status(500).send('Error deleting user and boxes');
    }
};

async function shareBox(boxId, recipientEmail, req, res) {
    console.log('Recipent:', recipientEmail)
    
    try {
        // Assuming box details are fetched from the database
        const box = await db.query('SELECT * FROM boxes WHERE id = ?', [boxId]);
        if (!box.length) {
            return res.status(404).send('Box not found.');
        }

        const boxOwner = box[0].box_owner;
        const boxName = box[0].box_name;
        const boxPin = box[0].box_pin;
        const boxLink = `http://localhost:3000/share/${boxId}`;
        
        // Prepare the email content
        let emailText = `Click here to view the shared label: ${boxLink}`;
        let emailHtml = `<p><strong>${boxOwner}</strong> has shared their label <strong>(${boxName})</strong> with you!</p>
                         <p>Click <a href="${boxLink}">here</a> to view it.</p>`;
        
        // Conditionally add the box pin to the email if it exists
        if (boxPin !== null) {
            emailText += ` The pin for this box is: ${boxPin}.`;
            emailHtml += `<p>The pin for this box is: <strong>${boxPin}</strong>.</p>`;
        }
        
        // Prepare the mail options
        const mailOptions = {
            from: 'moveoutnoreply@gmail.com',
            to: recipientEmail,
            subject: `${boxOwner} has shared their label (${boxName}) with you!`,
            text: emailText,   // Plain text version
            html: emailHtml    // HTML version
        };
        

        // Send the email
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log('Error sending email:', error);
                res.status(500).send('Failed to send email.');
            } else {
                console.log('Email sent:', info.response);
                res.status(200).send('Label shared successfully.');
            }
        });
    } catch (error) {
        console.error('Error sharing label:', error);
        res.status(500).send('An error occurred while sharing the label.');
    }
}

cron.schedule('0 0 * * *', async () => {
    try {
        // Fetch users who have not logged in for 27 days
        const users = await db.query(`SELECT email, last_logged_in FROM users WHERE DATEDIFF(NOW(), last_logged_in) = 27`);

        users.forEach((user) => {
            const { email } = user;
            
            // Prepare the reminder email
            const mailOptions = {
                from: 'moveoutnoreply@gmail.com',
                to: email,
                subject: 'Your account will be deleted in 3 days!',
                text: `Dear user, your account is going to be deleted in 3 days due to inactivity. Please log in to keep all your boxes and labels safe.`,
                html: `<p>Dear user,</p><p>Your account is going to be deleted in 3 days due to inactivity. Please <a href="http://localhost:3000/login">log in</a> to keep all your boxes and labels safe.</p>`
            };

            // Send the email
            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log('Error sending reminder email:', error);
                } else {
                    console.log(`Reminder email sent to ${email}: ${info.response}`);
                }
            });
        });
    } catch (error) {
        console.error('Error checking last_logged_in status:', error);
    }
});

// Scheduled job to delete accounts after 30 days of inactivity
cron.schedule('0 0 * * *', async () => {
    try {
        const users = await db.query(`SELECT email FROM user WHERE DATEDIFF(NOW(), last_logged_in) >= 30`);

        users.forEach(async (user) => {
            const { email } = user;
            
            await db.query('DELETE FROM boxes WHERE box_owner = ?', [email]);

            await db.query('DELETE FROM user WHERE email = ?', [email]);

            const userDirectory = path.join(__dirname, '../uploads', email); 
            clearDirectory(userDirectory); 

            console.log(`Account and all data for ${email} have been deleted.`);
        });
    } catch (error) {
        console.error('Error deleting inactive accounts:', error);
    }
});



module.exports = {
    login,
    signup,
    sendMarketingEmail,
    sendDeleteConfirmationEmail,
    validateInput,
    validateInput2,
    checkUser,
    getUsers,
    deleteUser,
    shareBox,
    verify
};