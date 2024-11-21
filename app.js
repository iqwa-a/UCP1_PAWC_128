const express = require('express');
const todoRoutes = require('./routes/tododb.js');
const app = express();
require('dotenv').config();
const port = process.env.PORT || 3000;

const expressLayout = require('express-ejs-layouts')

const db = require('./database/db.js')

// pertemuan 7 session dan bycrypt
const session = require('express-session');
const authRoutes = require('./routes/authRoutes');
const { isAuthenticated } = require('./middleware/middleware.js');


app.use(express.static('public'));
app.use(expressLayout);

app.use(express.json());


// Konfigurasi express-session
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }  //Set ke true jika menggunakan HTTPS
}));


app.use('/todos', todoRoutes);
app.set('view engine', 'ejs');
app.get('/',isAuthenticated, (req, res) => {
    res.render('index', {
        layout: 'layouts/main-layouts.ejs'
    });
});

app.use(express.urlencoded({ extended: true }));

app.use('/', authRoutes);

app.get('/contact',isAuthenticated,(req, res) => {
    res.render('contact', {
        layout: 'layouts/main-layouts.ejs'
    });
        
});

app.get('/todo-view', (req, res) => {
    db.query('SELECT * FROM todos', (err, todos) => {
        if (err) return res.status(500).send('Internal Server Error');
        res.render('todo', {
            layout: 'layouts/main-layouts.ejs',
            todos: todos
        });
    });
});

app.use((req, res) => {
    res.status(404).send('404 - Page Not Found');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});

