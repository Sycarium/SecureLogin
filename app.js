const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const scrypt = require('scrypt');
const sanitizeHtml = require('sanitize-html');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const session = require('express-session');
const csurf = require('csurf');
const fs = require('fs');
const https = require('https');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');

const app = express();



mongoose.connect('mongodb://localhost:27017/mydatabase', { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

// Use session middleware
app.use(session({
  secret: 'your-secret-key', // Replace with a strong secret key
  resave: false,
  saveUninitialized: true,
}));

// Use CSRF middleware
app.use(csurf());

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Set up HTTPS with self-signed certificate (for development purposes)
const options = {
  key: fs.readFileSync('server-key.pem'),
  cert: fs.readFileSync('server-crt.pem'),
};

// just generating this key at random since I don't know what to put it as a basis.
const secretKey = crypto.randomBytes(32).toString('base64');
console.log('Generated Key:', secretKey);

// Sanitize user inputs middleware
app.use((req, res, next) => {
  // Validate and sanitize all user inputs
  for (const key in req.body) {
    if (key === 'username' && !validateUsername(req.body[key])) {
      res.status(400).send('Bad Request: Invalid username.');
      return;
    }

    if (key === 'password' && !validatePassword(req.body[key])) {
      res.status(400).send('Bad Request: Invalid password.');
      return;
    }

    req.body[key] = sanitizeHtml(req.body[key]);
  }
  next();
});

// Validation functions
const validateUsername = (username) => {
  // Use regex pattern for username validation (allowing only alphanumeric characters and underscores)
  const usernameRegex = /^[a-zA-Z0-9_]+$/;
  // Define minimum and maximum length constraints for username
  const minUsernameLength = 4;
  const maxUsernameLength = 20;

  return usernameRegex.test(username) && username.length >= minUsernameLength && username.length <= maxUsernameLength;
};

const validatePassword = (password) => {
  // Use regex pattern for password validation (at least one uppercase letter, one lowercase letter, and one digit)
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
  // Define minimum length constraint for password
  const minPasswordLength = 8;
  const maxPasswordLength = 20; // Adjust this value based on your security policies
  return passwordRegex.test(password) && password.length >= minPasswordLength && password.length <= maxPasswordLength;
};

//                       Middlewares

// HTTPS middleware
app.use((req, res, next) => {
  if (req.secure) {
    // Request is secure (over HTTPS)
    next();
  } else {
    // Redirect non-secure requests to the secure version
    res.redirect(`https://${req.headers.host}${req.url}`);
  }
});

// Middleware to generate and include CSRF token in responses
app.use((req, res, next) => {
  // Generate and include anti-CSRF token in the response locals
  res.locals.csrfToken = req.csrfToken();
  next();
});

// Middleware to include CSRF token in views
app.use((req, res, next) => {
  // Make the CSRF token available in the view engine (e.g., EJS)
  res.locals.csrfToken = res.locals.csrfToken;
  next();
});

// helmet with CSP middleware
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.example.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.example.com'],
      imgSrc: ["'self'", 'data:', 'https://cdn.example.com'],
      fontSrc: ["'self'", 'https://cdn.example.com'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
      blockAllMixedContent: [],
    },
  })
);

// Apply rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many requests from this IP, please try again after some time.',
});

app.use('/register', limiter); // Apply rate limiting to the registration endpoint
app.use('/login', limiter); // Apply rate limiting to the login endpoint

// Logging middleware
app.use(morgan('dev')); // Use the 'dev' pre-defined format for logging

// Function to generate CSRF token
function generateCsrfToken(req, res, next) {
  const secret = crypto.randomBytes(32).toString('base64');
  req.session.csrfSecret = secret;
  return csurf({ value: (req) => req.session.csrfSecret })(req, res, next);
}

// Middleware to update session expiration time
const updateSessionExpiration = (req, res, next) => {
    req.session.cookie.expires = new Date(Date.now() + 60 * 60 * 1000); // Extend session expiration to 1 hour
    req.session.cookie.maxAge = 60 * 60 * 1000; // Set the session max age to 1 hour
    next();
  };

  // Use the middleware to update session expiration for every request
app.use(updateSessionExpiration);


// Middleware to check session expiration and log out if needed
const checkSessionExpiration = (req, res, next) => {
    if (req.session.loggedIn && req.session.cookie.expires < new Date()) {
      // If the session is expired, log out the user
      req.session.destroy((err) => {
        if (err) {
          console.error('Error destroying session:', err);
        }
      });
    }
    next();
  };

  

// Use the middleware to check session expiration for every request
app.use(checkSessionExpiration);


// Registration backend
app.post('/register', generateCsrfToken, async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if the username already exists
    const foundUser = await User.findOne({ username });

    // Validate anti-CSRF token
    const csrfToken = req.body._csrf; // Assuming the token is included in the request body
    if (!validateCsrfToken(req.session.csrfSecret, csrfToken)) {
      res.status(403).send('Forbidden: CSRF token validation failed.');
      return;
    }

    if (foundUser) {
      // Username already exists
      res.send('Username already exists. Please choose another username.');
    } else {
      // Sanitize user inputs before hashing the password
      const sanitizedUsername = sanitizeHtml(username);
      const sanitizedPassword = sanitizeHtml(password);

      // Hash the password before saving to the database
      const hashedPassword = await scrypt.kdf(sanitizedPassword, { N: 16384, r: 8, p: 1 }, 64, 'base64');

      // Create a new user with the sanitized and hashed password
      const newUser = new User({
        username: sanitizedUsername,
        password: hashedPassword,
      });

      await newUser.save();

      // Log a successful registration
      console.log(`User registered: ${req.body.username}`);

      // Generate and send an access token upon successful registration
      const accessToken = jwt.sign({ username: sanitizedUsername }, secretKey, { expiresIn: '1h' });

      // Send a response to the client
      res.json({ message: 'Registration successful', accessToken, csrfToken: req.csrfToken() });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});
// Secure route that requires authentication
app.get('/Lake', requireAuth, (req, res) => {
  // Access to this route requires authentication
  // req.user contains the decoded information from the token

  // Check if the authenticated user is authorized to access the data
  if (req.params.username !== req.user.username) {
    res.status(403).send('Forbidden: You are not authorized to access this resource.');
  } else {
    // User is authorized, proceed with accessing the data
    res.send(`Welcome, ${req.user.username}!.`);
  }
});

// Login backend
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Validate anti-CSRF token
    const csrfToken = req.body._csrf; // Assuming the token is included in the request body
    if (!validateCsrfToken(req.session.csrfSecret, csrfToken)) {
      res.status(403).send('Forbidden: CSRF token validation failed.');
      return;
    }

    // Sanitize user inputs before searching the database
    const sanitizedUsername = sanitizeHtml(username);
    const sanitizedPassword = sanitizeHtml(password);

    // Find user in the database
    const foundUser = await User.findOne({ username: sanitizedUsername });

    if (foundUser) {
      // Compare the provided password with the stored hashed password
      const passwordMatch = await scrypt.verifyKdf(Buffer.from(foundUser.password, 'base64'), sanitizedPassword);

      if (passwordMatch) {
        // Authentication successful
        // Generate and send an access token upon successful login
        const accessToken = jwt.sign({ username: sanitizedUsername }, secretKey, { expiresIn: '1h' });

        // Log a successful login
        console.log(`User logged in: ${req.body.username}`);

           // Update user state/session to indicate they are logged in
           req.session.loggedIn = true;

           
    // Set initial session expiration time
    req.session.cookie.expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    req.session.cookie.maxAge = 60 * 60 * 1000; // 1 hour


        // Send a response to the client
        res.json({ message: 'Login successful', accessToken });
        res.redirect('/Lake'); 
      } else {
        // Authentication failed
        res.status(401).send('Invalid username or password.');
      }
    } else {
      // Authentication failed (user not found)
      res.status(401).send('Invalid username or password.');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

const PORT = 3000;
const HTTPS_PORT = 3001; // HTTPS port for secure connections
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

// Start the HTTPS server (for development purposes, use a valid certificate in production)
https.createServer(options, app).listen(HTTPS_PORT, () => {
  console.log(`Server is running on https://localhost:${HTTPS_PORT}`);
});
