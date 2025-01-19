const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

require('dotenv').config();
const dbPass = process.env.MONGO_PW;

const app = express();
app.use(cors());
app.use(express.json());

// Connect to database (MongoDB Atlas)
mongoose.connect('mongodb+srv://milaautio:' + dbPass + '@cluster0.ecmul.mongodb.net/study_planner?retryWrites=true&w=majority&appName=Cluster0', {});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  sections: [{ id: Number, title: String, tasks: [{ id: Number, text: String, completed: Boolean, notes: String }] }]
});

const User = mongoose.model('User', userSchema);

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'secretkey';

// Register a new user
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(201).json({ token });
  } catch (error) {
    console.log(error)
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Authenticate user via JWT token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// Fetch sections for the logged-in user
app.get('/api/sections', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    res.json(user.sections);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch sections' });
  }
});

// Save sections for the logged-in user
app.post('/api/sections', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    user.sections = req.body;
    await user.save();
    res.status(200).json({ message: 'Sections saved successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save sections' });
  }
});

// Server running on port 5001
app.listen(5001, () => {
  console.log('Server is running on port 5001');
});
