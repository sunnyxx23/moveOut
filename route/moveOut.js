'use strict';



const express       = require('express');
const crypto        = require('crypto');
const multer        = require('multer');
const path          = require('path');
const fs            = require('fs');
const jwt           = require('jsonwebtoken')
const mysql         = require('promise-mysql');
const config        = require('../db/config.json');
const router        = express.Router();
const myFuncs       = require('../src/myFuncs.js');
const QRCode        = require('qrcode');
let db;

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const token = req.cookies.jwt;
        if (!token) {
            return cb(new Error('No token provided'));
        }

        try {
            const decodedToken = jwt.verify(token, 'secretkey');
            const email = decodedToken.email;

            // Assuming the box's name is passed in the request, e.g., req.body.boxName
            const boxName = req.body.boxName; // Adjust this if it's coming from another source

            if (!boxName) {
                return cb(new Error('No box name provided'));
            }

            // Create user-specific folder and box-specific subfolder
            const userFolder = path.join(__dirname, '../uploads/', email, boxName);
            if (!fs.existsSync(userFolder)) {
                fs.mkdirSync(userFolder, { recursive: true });
            }

            cb(null, userFolder);
        } catch (err) {
            return cb(new Error('Invalid token'));
        }
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});


const upload = multer({ storage });

module.exports = router;

/**
 * Main function.
 * @async
 * @returns void
 */
(async function() {
    db = await mysql.createConnection(config);
    console.log('Database connected for routes')
    process.on('exit', () => {
        db.end();
    });
})();

router.get('/verify-email', async (req, res) => {
    const token = req.query.token;
    const secret = 'secretkey';

    try {
        await myFuncs.verify(req, res, token, secret)
        res.render('verify-email');
    } catch (err) {
        res.status(400).send('Invalid or expired token');
    }
});


router.get('/', (req, res) => {
    res.render('index');
});

router.get('/index', (req, res) => {
    res.render('index');
});

router.get('/about', (req, res) => {
    res.render('about');
});

router.get('/login', async (req, res) => {
    const confirmed = req.query.confirmed || ''; // Get the query parameter
    res.render('login', { confirmed});
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const results = await myFuncs.login(req, res, email, password);
        console.log(results);
        const errormsg = results.errorMessage;

        if (results.success && results.errormsg == null) {
            return res.redirect('/');
        } else {
            return res.render('login', { errormsg });
        }
    } catch (err) {
        console.log(err);
        return res.status(500).send('Error during login');
    }
});


router.get("/logout", (req, res) => {
    res.cookie('jwt', '', { maxAge: 1 });
    res.redirect("/");
});

router.get('/signup', async (req, res) => {
    res.render('signup');
});

router.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        const results = await myFuncs.signup(req, res, email, password);

        if (results.success) {
            return res.redirect(`/login?confirmed=Verify%20your%20email%20to%20login!`);
        } else {
            return res.render('signup', {
                emailError: results.emailErrors,
                passwordError: results.passwordErrors
            });
        }
    } catch (err) {
        console.log('signup error', err);
        return res.status(500).send('Error during registration.');
    }
});

router.get('/box', async (req, res) => {
    const labelsDir = path.join(__dirname, '../labels');
    
    // Read all label files (assumes PNG files)
    fs.readdir(labelsDir, (err, files) => {
        if (err) {
            console.error('Error reading labels directory:', err);
            return res.status(500).send('Error loading labels');
        }

        // Filter to only PNG files
        const labels = files.filter(file => file.endsWith('.png'));
        
        // Pass labels to the template
        res.render('box', { labels });
    });
});

router.post('/box/upload', upload.fields([
    { name: 'images' }, 
    { name: 'audios' }, 
    { name: 'texts' }
]), async (req, res) => {
    console.log(req.body);
    const token = req.cookies.jwt;
    const decodedToken = jwt.verify(token, 'secretkey');
    const email = decodedToken.email;
    const boxName = req.body.boxName;
    const notes = req.body.notes;
    const textFieldNames = req.body.textFieldName; // Get text field names
    const boxPrivate = req.body.boxPrivate === 'yes' ? 1 : 0; // Convert the string to boolean (1 or 0)
    const label = `/labels/${req.body.label}`;
    const boxPin = req.body.boxPin ? parseInt(req.body.boxPin) : null; // Get the 6-digit PIN or null
    let userFolder = path.join(__dirname, '../uploads/', email, boxName);

    try {
        fs.mkdirSync(userFolder, { recursive: true });

        const result = await db.query(
            'INSERT INTO boxes (box_name, box_owner, box_path, box_private, label, box_pin) VALUES (?, ?, ?, ?, ?, ?)',
            [path.basename(userFolder), email, userFolder, boxPrivate, label, boxPin]
        );

        if (!result) {
            console.log('ERROR INSERTING INTO DB');
            return;
        }

        if (Array.isArray(notes)) {
            notes.forEach((note, index) => {
                const noteFileName = (Array.isArray(textFieldNames) && textFieldNames[index]) || `note${index + 1}`;
                const noteFilePath = path.join(userFolder, `${noteFileName}.txt`); // Use userFolder instead of textfield
                fs.writeFileSync(noteFilePath, note);
            });
        } else if (notes) {
            // In case there's only one note (not an array), save it as the first textFieldName
            const noteFileName = textFieldNames || 'note1'; // Use the first name or default
            const noteFilePath = path.join(userFolder, `${noteFileName}.txt`); // Use userFolder instead of textfield
            fs.writeFileSync(noteFilePath, notes);
        }

        res.redirect(`/${email}/boxes`);
    } catch (error) {
        console.error('Error uploading files or creating box:', error);
        res.status(500).send('Error uploading files or creating box');
    }
});

router.get('/:user/boxes', async (req, res) => {
    const userEmail = req.params.user;

    const query = 'SELECT id, box_name, box_private FROM boxes WHERE box_owner = ?';
    const boxes = await db.query(query, [userEmail]);

    res.render('my-boxes', { boxes }); // Pass boxes and user to the view
});

router.get('/:id', async (req, res) => {
    const boxId = req.params.id;
    const user = res.locals.user.email;
    const sql = 'SELECT * FROM boxes WHERE id = ?';
    
    try {
        const [box] = await db.query(sql, [boxId]);

        console.log(box);

        // Check if the box exists
        if (!box) {
            return res.status(404).send('Box not found');
        }

        // If box is private and the current user is not the owner, prompt for a PIN
        if (box.box_private === 1 && box.box_owner !== user) {
            return res.render('enter-pin', { boxId });  // Render PIN entry page
        }

        // Proceed to show box details if the user is the owner or the box is public
        if (box.box_owner === user || box.box_private === 0) {
            return await showBoxDetails(res, box, boxId);  // Helper function to show box details
        }

        res.redirect('/');
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

router.post('/:id/verify-pin', async (req, res) => {
    const boxId = req.params.id;
    const { pin } = req.body;  // Get the submitted PIN from the form

    try {
        const sql = 'SELECT * FROM boxes WHERE id = ?';
        const [box] = await db.query(sql, [boxId]);

        // Check if the box exists and if the PIN matches
        if (box && box.box_pin == pin) {
            return await showBoxDetails(res, box, boxId);  // Helper function to show box details
        } else {
            return res.render('enter-pin', { boxId, error: 'Incorrect PIN, please try again' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

async function showBoxDetails(res, box, boxId, showShareButton = true) {
    const boxPath = box.box_path;

    // Read the box directory to find files
    fs.readdir(boxPath, async (err, files) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error reading box files');
        }

        // Filter files based on their extensions
        const images = files.filter(file => ['.jpg', '.jpeg', '.png', '.gif'].includes(path.extname(file).toLowerCase()));
        const audios = files.filter(file => ['.mp3', '.wav', '.m4a'].includes(path.extname(file).toLowerCase()));
        const notes = files.filter(file => path.extname(file).toLowerCase() === '.txt');

        // Generate URLs for the files
        const imagePaths = images.map(file => `/uploads/${box.box_owner}/${encodeURIComponent(box.box_name)}/${file}`);
        const audioPaths = audios.map(file => `/uploads/${box.box_owner}/${encodeURIComponent(box.box_name)}/${file}`);

        // Read note contents
        const noteData = await Promise.all(notes.map(file => {
            return new Promise((resolve, reject) => {
                const filePath = path.join(boxPath, file);
                fs.readFile(filePath, 'utf-8', (err, data) => {
                    if (err) reject(err);
                    resolve({ name: file, content: data });
                });
            });
        }));

        // Generate a QR code for the box URL
        const boxUrl = `http://localhost:3000/${boxId}`;
        const qrCodeDataUrl = await QRCode.toDataURL(boxUrl);

        // Render the box-detail page with all the data
        res.render('box-detail', {
            box,
            images: imagePaths,
            audios: audioPaths,
            notes: noteData,
            qrCode: qrCodeDataUrl,
            showShareButton,  // Pass the flag to control the visibility of the share button
            res
        });
    });
};

router.get('/admin/users', async (req, res) => {
    if (res.locals.admin === true) {
        let users = await myFuncs.getUsers();
        res.render('getUsers', { users });
    } else {
        res.status(403).send('Access denied.');
    }
});

router.get('/disable/:user', async (req, res) => {
    const email = req.params.user;
    try {
        // Query to disable the user (set isDisabled = 1)
        const disableQuery = `UPDATE user SET isDisabled = 1 WHERE email = ?`;
        await db.query(disableQuery, [email]);
        res.redirect('/admin/users');
    } catch (error) {
        console.error('Error disabling user:', error);
        req.flash('error', 'Error disabling user.');
        res.redirect('/admin/users');
    }
});

router.get('/enable/:user', async (req, res) => {
    const email = req.params.user;
    try {
        // Query to enable the user (set isDisabled = 0)
        const enableQuery = `UPDATE user SET isDisabled = 0 WHERE email = ?`;
        await db.query(enableQuery, [email]);
        res.redirect('/admin/users');
    } catch (error) {
        console.error('Error enabling user:', error);
        req.flash('error', 'Error enabling user.');
        res.redirect('/admin/users');
    }
});

router.get('/marketing/:user', async (req, res) => {
    const email = req.params.user;
    try {
        myFuncs.sendMarketingEmail(email);  // Send marketing email
        console.log(`Marketing email sent to ${email}`);
        res.send('Marketing email sent successfully');  // Send response to client
    } catch (error) {
        console.log('Error in /marketing/:user route:', error);
        res.redirect('/');
    }
});

router.get('/user/:user', async (req, res) => {
    const user = req.params.user;
    res.render('user', { user });
});

router.get('/delete/:user', async (req, res) => {
    const user = req.params.user;
    console.log(user);
    // Send delete confirmation email
    myFuncs.sendDeleteConfirmationEmail(user);

    // Log out the user
    res.cookie('jwt', '', { maxAge: 1 }); // Clear the JWT token

    // Redirect to login with a confirmation message
    res.redirect(`/login?confirmed=Check your email to delete`);
});

router.get('/final-delete/:user', async (req, res) => {
    const user = req.params.user;

    await myFuncs.deleteUser(req, res, user);

    res.redirect(`/login?confirmed=Account has been deleted`);
});

router.get('/:id/share', async (req, res) => {
    const boxId = req.params.id;
    const recipientEmail = req.query.email;
    
    if (!recipientEmail) {
        return res.status(400).send('Recipient email is required.');
    }
    
    console.log('Sharing box', boxId, 'with', recipientEmail);
    
    try {
        await myFuncs.shareBox(boxId, recipientEmail, req, res);
    } catch (error) {
        console.log('Error:', error);
        res.status(500).send('Failed to share the label.');
    }
});

router.get('/share/:id', async (req, res) => {
    const boxId = req.params.id;
    const sql = 'SELECT * FROM boxes WHERE id = ?';

    try {
        const [box] = await db.query(sql, [boxId]);

        // Check if the box exists
        if (!box) {
            return res.status(404).send('Box not found');
        }

        // If box is private, prompt for a PIN
        if (box.box_private === 1) {
            return res.render('enter-pin', { boxId });  // Render PIN entry page
        }

        // Show box details for public or shared boxes
        return await showBoxDetails(res, box, boxId, false);  // Pass "false" to hide share button
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});