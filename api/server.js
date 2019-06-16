const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SessionStore = require('connect-session-knex')(session);

const server = express();

const sessionConfig = {
    name: 'session',
    secret: 'session secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 60 * 60 * 1000,
        secure: false,
        httpOnly: false
    },
    store: new SessionStore({
        knex: require('../database/dbConfig'),
        tablename: 'sessions',
        sidfieldname: 'sid',
        createtable: true,
        clearInterval: 60 * 60 * 1000
    })
}

server.use(session(sessionConfig))
server.use(express.json());
server.use(cors());
server.use(helmet());

const Users = require('../users/users-model.js');

server.get('/', (req, res) => {
    res.send("Up and running")
})

// Create new user
server.post('/api/register', (req, res) => {
    let user = req.body;

    if (!user.username||!user.password){
        return res.status(500).json({message: "Must include username and password"})
    }

    const hash = bcrypt.hashSync(user.password, 12);

    user.password = hash;
  
    Users.add(user)
        .then(user => {
            res.status(201).json(user)
        })
        .catch(err => {
            res.status(500).json(err)
        })
})

// Sign in

server.post('/api/login', (req, res) => {
    let {username, password} = req.body;

    Users.findBy({username})
    .first()
    .then(user => {
        if (user && bcrypt.compareSync(password, user.password)){
            req.session.user = user;
            res.status(200).json({message: `Welcome ${username}`})
        } else {
            res.status(401).json({message: "Invalid credentials"})
        }
    })
    .catch(err => {
        res.status(500).json(err)
    })
})

// Protected Route

server.get('/api/restricted/users', authorize, (req, res) => {
    Users.find()
    .then(users => {
        res.json(users)
    })
    .catch(err => {
        res.status(500).json(err)
    })
})

// Authorization Middleware

function authorize(req, res, next){
    // const username = req.headers['x-username'];
    // const password = req.headers['x-password'];

    // if (!username||!password){
    //     res.status(401).json({message: "Invalid credentials"})
    // }

    // Users.findBy({username})
    // .first()
    // .then(user => {
    //     if(user && bcrypt.compareSync(password, user.password)){
    //         next()
    //     } else {
    //         res.status(401).json({message: "Invalid credentials"})
    //     }
    // })
    // .catch(err => {
    //     res.status(500).json(err)
    // })
    if (req.session && req.session.user){
        next()
    } else {
        res.status(401).json({message: "You are not authorized"})
    }
}

module.exports = server;