var express = require('express');
var app = express();

app.get('/', function (req, res) {
    res.send('Hello World!');
    });

app.listen(80);
console.log('Server running on port 80');