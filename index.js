const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const saltRounds = 10;
const myPlaintextPassword = 's0/\/\P4$$w0rD';
const protected = require('./middleware/protected');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;

  // validate user
  if(user){
    // hash the password
    const hash = bcrypt.hashSync(user.password, 8) // the 8 is the number of rounds

    // override the password with the hash
    user.password = hash;
  }

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      // validate user password to hashed passwrod in DB
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/users', protected, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.get('/api/hash', (req, res) => {
  const password = req.headers.authorization;

  if(password){
    // the 8 is how we slow down hackers, trying to pre-gen hashs
  const hash = bcrypt.hashSync(password, 10) // the 8 is the number of rounds
  // a good starting value is 14
  res.status(200).json({ hash });
  } else {
    res.status(400).json({
      message: 'please provide credentials'
    })
  }
})

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
