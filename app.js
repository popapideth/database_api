var express = require('express');
var cors = require('cors');
var app = express();
var bodyParser = require('body-parser');
var jsonParser = bodyParser.json();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const saltRounds = 10;
const secret = 'fullstack-login-2024';

app.use(cors());

// Retry logic for connecting to the database
const mysql = require('mysql2');
const maxRetries = 5;
let retries = 0;
let connection;

function connectToDatabase() {
    connection = mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_DATABASE,
    });

    connection.connect(err => {
        if (err && retries < maxRetries) {
            console.log(`Database connection failed. Retrying in 5 seconds... (${++retries}/${maxRetries})`);
            setTimeout(connectToDatabase, 5000);
        } else if (err) {
            console.error("Max retries reached. Could not connect to the database.");
        } else {
            console.log("Connected to the database successfully.");
        }
    });
}

// Call the connectToDatabase function to establish the connection
connectToDatabase();

// Endpoint for user registration
app.post('/register', jsonParser, function (req, res) { 
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        connection.execute(
            'INSERT INTO user (email, password, fname, lname) VALUES (?, ?, ?, ?)',
            [req.body.email, hash, req.body.fname, req.body.lname],
            function(err, results) {
                if (err) {
                    res.json({status: 'ERROR', message: err});
                    return;
                }
                res.json({status: 'OK'});
            }
        );
    });  
});

// Endpoint for login
app.post('/login', jsonParser, function (req, res) {
    connection.execute(
        'SELECT * FROM user WHERE email=?',
        [req.body.email],
        function(err, user) {
            if (err) {
                res.json({status: 'ERROR', message: err});
                return;
            }
            if (user.length === 0) {
                res.json({status: 'ERROR', message: 'No user found'});
                return;
            }
            bcrypt.compare(req.body.password, user[0].password, function(err, isLogin) {
                if (isLogin) {
                    var token = jwt.sign({ email: user[0].email }, secret, { expiresIn: '1h' });
                    res.json({status: 'OK', message: 'Login success', token});
                } else {
                    res.json({status: 'ERROR', message: 'Login failed'});
                }       
            });
        }
    );
}); 

// Endpoint for token authentication
app.post('/authen', jsonParser, function (req, res) {
    try {
        const token = req.headers.authorization.split(' ')[1];
        var decoded = jwt.verify(token, secret);
        res.json({status: 'OK', decoded});
    } catch (error) {
        res.json({status: 'ERROR', message: error.message});
    }
});

// Endpoint to retrieve data
app.get('/data', function(req, res) {
    connection.query(`
        SELECT 
            companies.*, 
            contacts.*, 
            profile_changes.*, 
            team_members.*,
            investments.*
        FROM 
            companies
        LEFT JOIN contacts ON companies.company_id = contacts.company_id
        LEFT JOIN profile_changes ON companies.company_id = profile_changes.company_id
        LEFT JOIN team_members ON companies.company_id = team_members.company_id
        LEFT JOIN investments ON companies.company_id = investments.company_id
    `, function(error, results) {
        if (error) throw error;
        res.json(results);
    });
});

// Start the server
app.listen(4444, function () {
    console.log('CORS-enabled web server listening on port 4444');
});
