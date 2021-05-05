const express = require('express');

const app = express();
const routes = require('./routes');
const path = require('path');

app.set('view engine', 'ejs');

app.set('views', path.join(__dirname, 'views'));
app.get('/', routes);
app.post('/register', routes);
app.get('/login', routes);
app.post('/login', routes);
app.get('/success', routes);
app.get('/logout', routes);
const PORT = process.env.PORT || 200;

app.listen(PORT, () => {
    console.log("Server is now listening on port -> ", PORT, ':)');
})