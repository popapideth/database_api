var express = require('express');
var cors = require('cors');
var app = express();
// Body parser คือตัวmiddlewareของexpress ที่ทำให้เราจัดการbodyที่มีการฝังข้อมูลกับเส้นrequestได้
var bodyParser = require('body-parser');
var jsonParser = bodyParser.json();
// ไลบรารีที่ใช้สำหรับแฮชรหัสผ่าน 
const bcrypt = require('bcryptjs');
const saltRounds = 10// saltRounds ใช้gen hash pass
// JSON web tokenในการยืนยันตัวเข้าสู่ระบบ
var jwt = require('jsonwebtoken');
const secret = 'fullstack-login-2024'// ตัวแปรที่ใช้gen token 
require('dotenv').config()

app.use(cors())

// get the client save data in database
const mysql = require('mysql2')
// connection database
const connection = mysql.createConnection({
    host : process.env.DB_HOST,
    user : process.env.DB_USER,
    password:process.env.DB_PASSWORD,
    database : process.env.DB_DATABASE
})



// POST /register gets JSON body // GET ใช้สำหรับดึงข้อมูล ขณะที่ POST ใช้สำหรับส่งข้อมูลใหม่ไปยัง server
app.post('/register', jsonParser, function (req, res, next) { 
    // Hash password ให้hash passจากreq.body.password แล้วจะได้ตัวแปรhash ก่อนแล้วค่อยเพิ่มเข้าฐานข้อมูล
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        // Prepared statement ในการส่งค่าเข้าในฐานข้อมูล queryของเรา 
        connection.execute(// ใช้insert dataเข้าตารางแทน
            'INSERT INTO user (email, password, fname, lname) VALUES (?, ?, ?, ?)',
            [req.body.email, hash, req.body.fname, req.body.lname],
            function(err,results,fields){
                // ERROR 
                if (err) {
                    res.json({status: 'ERROR', message: err})
                    return
                }
                res.json({status: 'OK'});
            }
        );
    });  
});

// login ใช้JSON web tokenในการยืนยันตัวเข้าสู่ระบบ แต่ละครั้งที่มีการlogin จะgen Token เพื่อไปใช้่ในการยืนยันตัว
app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(// ดึงข้อมูลที่ใช้ในการlogin มาดูว่าถูกต้องไหม
        'SELECT * FROM user WHERE email=?',
        [req.body.email],
        function(err,user,fields){
            // ERROR 
            if (err) {res.json({status: 'ERROR', message: err}); return;}
            // เช็คว่าเจอuserไหม
            if(user.length === 0) {res.json({status: 'ERROR', message: 'No user found'}); return;}
            // เทียบpass ที่ต้องเข้ามาตรงกับฐานข้อมูลไหม req.body.password, users[0].password
            bcrypt.compare(req.body.password, user[0].password, function(err, isLogin) {
                if (isLogin) {
                    // สร้างโทเคน (token) สำหรับยืนยันตัวตน ผู้ใช้ล็อกอินสำเร็จ เซิร์ฟเวอร์จะสร้างโทเคน JWT และส่งไปยังผู้ใช้ โดยโทเคนนี้จะใช้เป็นการยืนยันตัวในคำร้องขอถัดไปแทนการส่งรหัสผ่านทุกครั้ง
                    var token = jwt.sign({email : user[0].email}, secret, { expiresIn: '1h'}); 
                    res.json({status: 'OK', message: 'Login success', token});
                } 
                else{
                    res.json({status: 'ERROR', message: 'Login failed'});
                }       
            });
        }
    );
}); 

// check ว่าtokenส่งมาไหม
app.post('/authen', jsonParser, function (req, res, next) {
    try {
        const token = req.headers.authorization.split(' ')[1]
        // check token ว่า verify กับ jwtถูกต้องไหม ถูกต้องจะแสดงemail
        var decoded = jwt.verify(token, secret);
        res.json({status: 'OK', decoded});
    } catch (error) {
        res.json({status: 'ERROR', message: err.message});
    }
});

// -----------data-----------------
app.get('/data', function(req, res, next){
    connection.query(`
        SELECT 
            companies.*, 
            contacts.*, 
            profile_changes.*, 
            team_members.*
        FROM 
            companies
        LEFT JOIN contacts ON companies.company_id = contacts.company_id
        LEFT JOIN profile_changes ON companies.company_id = profile_changes.company_id
        LEFT JOIN team_members ON companies.company_id = team_members.company_id
    `, function(error, results, fields){
        if(error) throw error;
        res.json(results)
    })
})


app.listen(4444, function () {
  console.log('CORS-enabled web server listening on port 4444')
});

