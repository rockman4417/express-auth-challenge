const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(express.json())
const accessTokenSecret = 'youraccesstokensecret';

const users = []

const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];
        console.log(token)

        jwt.verify(token, accessTokenSecret, (err, user) => {
            if (err) {
                console.log("err", err)
                return res.sendStatus(403);
            }

            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

app.get('/users', (req, res) => {
  res.json(users)
})

app.post('/sign-up', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    const user = { name: req.body.name, password: hashedPassword }
    users.push(user)
    res.status(201).send()
  } catch {
    res.status(500).send()
  }
})

app.post('/sign-in', async (req, res) => {
  const user = users.find(user => user.name === req.body.name)
  if (user == null) {
    return res.status(400).send('Cannot find user')
  }
  try {
    if(await bcrypt.compare(req.body.password, user.password)) {
      const token = generateAccessToken({ username: req.body.name });
      res.json(token);
    } else {
      res.send('Not Allowed')
    }
  } catch {
    res.status(500).send()
  }
})

app.get('/me', authenticateJWT, async (req, res) => {
    try {
      res.send(req.user)
    } catch {
      res.status(500).send()
    }
})

const generateAccessToken = (username) => {
    return jwt.sign(username, accessTokenSecret);
}

app.listen(3000)
