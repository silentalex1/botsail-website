const express = require('express');
const path = require('path');
const app = express();
const port = 3000;

app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/botsail', (req, res) => {
    res.sendFile(path.join(__dirname, 'botsail.html'));
});

app.get('/myapps', (req, res) => {
    res.sendFile(path.join(__dirname, 'myapps.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'adminpanel.html'));
});

app.get('/admindashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'admindashboard.html'));
});

app.use((req, res) => {
    res.status(404).send('Page not found');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
