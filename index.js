require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const { MongoClient } = require('mongodb');
const path = require('path');
const helmet = require('helmet');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;
const mongoUrl = process.env.MONGO_URL;
const dbName = process.env.MONGO_DB;
const port = process.env.PORT;

let db;

MongoClient.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(client => {
    db = client.db(dbName);
    console.log('Connected to MongoDB');
  })
  .catch(error => console.error('Failed to connect to MongoDB:', error));

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public')); // Specify the views directory
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"], // Remove 'unsafe-inline' if possible
    },
  })
);

// Session configuration
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // For development, change to true if using HTTPS in production
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport Discord OAuth2 strategy
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: "https://api.yourdomain.com/auth/discord/callback", // Must match the redirect URI
  scope: ['identify', 'email'],
},
async (accessToken, refreshToken, profile, done) => {
  try {
    const collection = db.collection('Subscribers');
    let user = await collection.findOne({ userID: profile.id });

    if (!user) {
      return done(null, false, { message: 'User not found in database' });
    }

    const token = jwt.sign({ id: user.userID, username: user.username }, JWT_SECRET);

    await collection.updateOne(
      { userID: profile.id },
      { $set: { apiKey: token } }
    );

    return done(null, { ...user, apiKey: token });
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.userID);
});

passport.deserializeUser(async (userID, done) => {
  try {
    const user = await db.collection('Subscribers').findOne({ userID });
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Routes
// Discord OAuth login
app.get('/auth/discord', passport.authenticate('discord'));

// Discord OAuth callback
app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/home');
  }
);

app.get('/home', checkAuthentication, (req, res) => {
  const user = req.user;
  res.render('home', {
    username: user.username,
    userID: user.userID,
    apiKey: user.apiKey
  });
});

// Re-roll API key
app.post('/re-roll', checkAuthentication, async (req, res) => {
  const user = req.user;
  
  // Generate a new JWT token without expiration
  const newApiKey = jwt.sign({ id: user.userID, username: user.username }, JWT_SECRET);

  // Update the user's API key in the database
  await db.collection('Subscribers').updateOne(
    { userID: user.userID },
    { $set: { apiKey: newApiKey } }
  );

  req.user.apiKey = newApiKey; // Update session API key
  res.redirect('/home');
});

// Logout route
app.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) {
      return res.status(500).send('Error logging out');
    }
    res.redirect('/login');
  });
});

// Middleware to check if the user is authenticated
function checkAuthentication(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// JWT-based authentication for API routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied, token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

//Authentication to Endpoints you only want Admins to access!
const authenticateAdminToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.error('No token provided');
    return res.status(401).json({ error: 'Access denied, token missing' });
  }

  try {
    if (token !== process.env.ADMIN_TOKEN) {
      console.error('Token not found in database:', token);
      return res.status(403).json({ error: 'Invalid token' });
    }
    const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log('Token verified', userIp);
    next();
  } catch (error) {
    console.error('Failed to authenticate token:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// API Status
app.get('/api/status', async (req, res) => {
  try {
      res.json({'Status':'Online', 'version':'1.0.0', 'Developer':'Created by Euphoria Development!'});
  } catch (error) {
    console.error('Failed to fetch data:', error);
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});  

app.get('/', (req, res) => {
  const docsPath = path.join(__dirname, 'public', 'docs.html');
  res.sendFile(docsPath);
});

  const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      const userFolder = path.join(__dirname, 'public/images', req.user.userID);
      if (!fs.existsSync(userFolder)) {
        fs.mkdirSync(userFolder, { recursive: true }); // Create user folder if it doesn't exist
      }
      cb(null, userFolder);
    },
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`); // Use timestamp to avoid filename conflicts
    }
  });

const upload = multer({ storage: storage });

// Serve the login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Middleware to protect the upload page and route
app.get('/upload', checkAuthentication, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'upload.html'));
});

app.post('/api/upload', checkAuthentication, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Please upload an image file.' });
  }

  const imageUrl = `/images/${req.user.userID}/${req.file.filename}`; // Store image URL with userID
  res.status(200).json({ message: 'Image uploaded successfully!', imageUrl });
});

app.get('/api/user/images', checkAuthentication, (req, res) => {
  const userFolder = path.join(__dirname, 'public/images', req.user.userID);

  // Check if the user's folder exists
  if (!fs.existsSync(userFolder)) {
      return res.json([]); // No images if folder doesn't exist
  }

  // Read the directory and list all image files
  fs.readdir(userFolder, (err, files) => {
      if (err) {
          return res.status(500).json({ error: 'Failed to list images.' });
      }

      // Filter to include only image files
      const images = files.filter(file => /\.(jpg|jpeg|png|gif|webp)$/.test(file));
      const imageUrls = images.map(image => ({
          imageUrl: `/images/${req.user.userID}/${image}`
      }));

      res.json(imageUrls); // Return the image URLs in the format {imageUrl: ...}
  });
});

app.delete('/api/user/images/:filename', checkAuthentication, (req, res) => {
  const userID = req.user.userID; // Get the current user's ID from the session or JWT
  const filename = req.params.filename;

  // Construct the full path to the image in the user's folder
  const imagePath = path.join(__dirname, 'public', 'images', userID, filename);

  // Check if the file exists before attempting to delete it
  if (!fs.existsSync(imagePath)) {
      return res.status(404).json({ error: 'File not found' });
  }

  // Attempt to delete the file
  fs.unlink(imagePath, (err) => {
      if (err) {
          return res.status(500).json({ error: 'Failed to delete image' });
      }

      res.json({ message: 'Image deleted successfully!' });
  });
});

// Example route to log out and destroy the session
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Error logging out');
    }
    res.redirect('/login');
  });
});

app.get('/api/images', (req, res) => {
  const imagesDir = path.join(__dirname, 'public', 'images');
  
  // Read the directory and list all image files
  fs.readdir(imagesDir, (err, files) => {
    if (err) {
      console.error('Failed to list images:', err);
      return res.status(500).json({ error: 'Failed to list images' });
    }

    // Filter for image files only (e.g., jpg, png)
    const images = files.filter(file => /\.(jpg|jpeg|png|gif|webp)$/.test(file));
    
    // Return the list of image file names
    res.json(images);
  });
});

// Serve the gallery page (protected by authentication)
app.get('/gallery', checkAuthentication, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'gallery.html'));
});

// API route to delete an image (protected by authentication)
app.delete('/api/user/images/:filename', checkAuthentication, async (req, res) => {
  const userID = req.user.userID; // Get the current user's ID from the session or JWT
  const filename = req.params.filename;

  // Construct the full path to the image in the user's folder
  const imagePath = path.join(__dirname, 'public', 'images', userID, filename);
  
  console.log('Attempting to delete file:', imagePath);

  try {
    // Check if the file exists before attempting to delete it
    if (!fs.existsSync(imagePath)) {
      console.error('File does not exist:', imagePath);
      return res.status(404).json({ error: 'File not found' });
    }

    // Attempt to delete the file from the filesystem
    fs.unlink(imagePath, async (err) => {
      if (err) {
        console.error('Failed to delete image from filesystem:', err);
        return res.status(500).json({ error: 'Failed to delete image from filesystem' });
      }

      console.log('File deleted successfully from filesystem:', imagePath);

      // Remove the image reference from the MongoDB database
      const result = await db.collection('Images').deleteOne({
        userID: userID,
        imageUrl: `/images/${userID}/${filename}`,
      });

      if (result.deletedCount === 1) {
        console.log('Image deleted successfully from MongoDB:', filename);
        res.json({ message: 'Image deleted successfully!' });
      } else {
        console.error('Failed to delete image from MongoDB:', filename);
        res.status(500).json({ error: 'Failed to delete image from MongoDB' });
      }
    });
  } catch (error) {
    console.error('Error during image deletion process:', error);
    res.status(500).json({ error: 'Error during image deletion process' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`API server is running on http://localhost:${port}`);
});