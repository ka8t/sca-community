// Fixture clean : cookie Express avec httpOnly et secure
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
    res.cookie('session_id', 'abc123', { httpOnly: true, secure: true, sameSite: 'lax' });
    res.send('logged in');
});
