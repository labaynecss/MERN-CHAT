const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const ws = require('ws');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const app = express();

//
const port = process.env.PORT || 4040;
const bcryptSalt = bcrypt.genSaltSync(10);

//middlewares

dotenv.config();
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    credentials: true,
    origin: process.env.CLIENT_URL,
  }),
);

jwtSecret = process.env.JWT_SECRET;

//Database Configuration
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((err) => {
    console.error('Error connecting to MongoDB:', err);
  });

//Routes end-point

app.get('/profile', (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    jwt.verify(token, jwtSecret, {}, (err, userData) => {
      if (err) throw err;
      res.json(userData);
    });
  } else {
    res.status(401).json('no token');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const foundUser = await User.findOne({ username });
  if (foundUser) {
    const verify = bcrypt.compareSync(password, foundUser.password);
    if (verify) {
      jwt.sign(
        { userId: verify._id, username },
        jwtSecret,
        {},
        (err, token) => {
          if (err) throw err;
          res
            .cookie('token', token, { sameSite: 'none', secure: true })
            .status(201)
            .json({
              id: verify._id,
            });
        },
      );
    }
  }
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
    const createdUser = await User.create({
      username: username,
      password: hashedPassword,
    });
    jwt.sign(
      { userId: createdUser._id, username },
      jwtSecret,
      {},
      (err, token) => {
        if (err) throw err;
        res
          .cookie('token', token, { sameSite: 'none', secure: true })
          .status(201)
          .json({
            id: createdUser._id,
          });
      },
    );
  } catch (err) {
    if (err) throw err;
    res.status(500).json('An error occurred during registration');
  }
});

// Port Server && WebSocket
app.get('/', (req, res) => {
  res.json(`Server is runnning `);
});

const server = app.listen(port, () => {
  console.log(`Server is running at Port ${port}`);
});

const wss = new ws.WebSocketServer({ server });

wss.on('connection', (connection, req) => {
  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookieString = cookies
      .split(';')
      .find((str) => str.startsWith('token ='));
    if (tokenCookieString) {
      const token = tokenCookieString.split('=')[1];
      if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
          if (err) throw err;
          const { userId, username } = userData;
          connection.userId = userId;
          connection.username = username;
        });
      }
    }
  }
  [...wss.clients].forEach((client) => {
    client.send(
      JSON.stringify(
        [...wss.clients].map((c) => ({
          userId: c.userId,
          username: c.username,
        })),
      ),
    );
  });
});
