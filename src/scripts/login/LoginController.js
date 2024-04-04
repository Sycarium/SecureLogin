const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');

const app = express();

// Connect to MongoDB (Make sure you have MongoDB running)
mongoose.connect('mongodb://localhost:27017/mydatabase', { useNewUrlParser: true, useUnifiedTopology: true });

// Create a User schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Login view
app.get('/login', (req, res) => {
  res.render('login');
});

// Login backend
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Find user in the database
  User.findOne({ username, password }, (err, foundUser) => {
    if (err) {
      console.log(err);
      res.redirect('/login');
    } else {
      if (foundUser) {
        // Authentication successful
        res.send('Login successful!');
      } else {
        // Authentication failed
        res.send('Invalid username or password.');
      }
    }
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
// ... (previous code)

// Registration view
app.get('/register', (req, res) => {
    res.render('register');
  });
  
  // Registration backend
  app.post('/register', (req, res) => {
    const { username, password } = req.body;
  
    // Check if the username already exists
    User.findOne({ username }, (err, foundUser) => {
      if (err) {
        console.log(err);
        res.redirect('/register');
      } else {
        if (foundUser) {
          // Username already exists
          res.send('Username already exists. Please choose another username.');
        } else {
          // Create a new user and save to the database
          const newUser = new User({
            username,
            password,
          });
  
          newUser.save((err) => {
            if (err) {
              console.log(err);
              res.redirect('/register');
            } else {
              // Registration successful
              res.send('Registration successful!');
            }
          });
        }
      }
    });
  });