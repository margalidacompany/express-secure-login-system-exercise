const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const JwtStrategy = require('passport-jwt').Strategy
const fs = require('fs')
const https = require('https')
const path = require('path')
const argon2 = require('argon2')


const USERS_DB_FILE = './users.json'
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits




/*
Certificates
*/
const options = {
  key: fs.readFileSync('./certs/key.pem'),
  cert: fs.readFileSync('./certs/cert.pem')
}

const port = 443 //changed for https
const app = express()




/*
Middlewares
*/
app.use(logger('dev'))
app.use(cookieParser()) // needed to retrieve cookies
app.use(express.static('public')) //folder public where html
app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize()) // we load the passport auth middleware to our express application. It should be loaded before any route.




/*
User management functions
*/
const loadUsers = () => {
  if (!fs.existsSync(USERS_DB_FILE)) return []
  return JSON.parse(fs.readFileSync(USERS_DB_FILE, 'utf8'))
}

const saveUsers = (users) => {
  fs.writeFileSync(USERS_DB_FILE, JSON.stringify(users, null, 2))
}

const registerUser = async (username, password, mode = "slow") => { // Can be changed to fast
    let users = loadUsers();
    const existingUser = users.find(u => u.username === username);
    if (existingUser) throw new Error("This user already exists, try another username");

    const argon2Config = {
        fast: { timeCost: 2, memoryCost: 65536, parallelism: 1 }, // <1s
        slow: { timeCost: 5, memoryCost: 1048576, parallelism: 4 } // >3s
    };
  const hashedPassword = await argon2.hash(password) // Use Argon2

  users.push({ username, password: hashedPassword })
  saveUsers(users)
  console.log(`User ${username} registered!`)
}

const verifyPassword = async (username, password) => {
  let users = loadUsers()
  const user = users.find(u => u.username === username)
  if (!user) return false

  return await argon2.verify(user.password, password) 
}




/*
Passport configuration
*/
passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username', // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password', // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
  async function (username, password, done) {
    try {
      const isValid = await verifyPassword(username, password)
      if (isValid) {
        return done(null, { username })
      }
      return done(null, false, { message: 'INCORRECT user or password' })
    } catch (err) {
      return done(err)
    }
  }
))

passport.use('jwtCookie', new JwtStrategy(
  {
    jwtFromRequest: (req) => {
      if (req && req.cookies) { return req.cookies.jwt }
      return null
    },
    secretOrKey: jwtSecret
  },
  function (jwtPayload, done) {
    if (jwtPayload.sub) {
      const user = {
        username: jwtPayload.sub,
        description: 'one of the users that deserve to get to this server',
        role: jwtPayload.role ?? 'user'
      }
      return done(null, user)
    }
    return done(null, false)
  }
))




/*
Public paths
*/
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'))
})

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'))
})

app.get('/logout', (req, res) => {
  res.clearCookie('jwt') 
  res.redirect('/login') 
})


/*
Protected paths
*/
app.get('/home',
  passport.authenticate('jwtCookie', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'))
  }
)

app.get('/',
  passport.authenticate(
    'jwtCookie',
    { session: false, failureRedirect: '/login' }
  ),
  (req, res) => {
    res.redirect('/home')
  }
)




/*
Authentification paths
*/
app.post('/register', async (req, res) => {
  const { username, password } = req.body
  if (!username || !password) {
    return res.status(400).json({ message: 'Please provide a username and password' })
  }

  try {
    await registerUser(username, password)
    res.send(`
      <h2>Registration successful!</h2>
      <p>You will be redirected to the login page in 3 seconds...</p>
      <script>
        setTimeout(() => { window.location.href = "/login"; }, 3000);
      </script>
    `)
  } catch (error) {
    res.status(400).json({ message: error.message })
  }
})


app.post('/login',
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => {
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
    res.redirect('/home')

    // And let us log a link to the jwt.io debugger for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)




//errors
app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})



//initializatio 
https.createServer(options, app).listen(port, () => {
  console.log(`HTTPS server running at https://localhost:${port}`)
})
