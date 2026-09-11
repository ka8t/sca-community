// Fixture vulnérable : path traversal JavaScript — fichier ouvert avec entrée utilisateur
const fs = require('fs');
const express = require('express');
const app = express();

app.get('/download', (req, res) => {
    const data = fs.readFileSync(req.query.file);
    res.send(data);
});

// Multi-ligne : readFileSync sur plusieurs lignes
app.get('/download2', (req, res) => {
    const data = fs.readFileSync(
        req.query.file
    );
    res.send(data);
});
