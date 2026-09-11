// Fixture vulnérable : cookie Express sans httpOnly
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
    res.cookie('session_id', 'abc123');
    res.send('logged in');
});

// Multi-ligne : res.cookie sur plusieurs lignes
app.post('/login2', (req, res) => {
    res.cookie(
        'session_id',
        'abc123'
    );
    res.send('logged in');
});
