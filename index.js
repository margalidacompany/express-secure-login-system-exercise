require('dotenv').config();
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

const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy; //oauth

const { Issuer, Strategy: OpenIDConnectStrategy } = require('openid-client'); //openid

const RadiusClient = require('node-radius-client'); //radius
const {
  dictionaries: {
    rfc2865: { file, attributes },
  },
} = require('node-radius-utils');

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
app.use(session({
  //secret: process.env.SESSION_SECRET, 
  secret: require('crypto').randomBytes(32).toString('base64url'),
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize()) // we load the passport auth middleware to our express application. It should be loaded before any route.
app.use(passport.session()); // indicate to express that passport manages sessions

passport.serializeUser((user, done) => done(null, user)); //when good oauth2.0 it saves the user in the session
passport.deserializeUser((obj, done) => done(null, obj)); //saves the user when changes pages



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

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: 'https://localhost:443/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  const users = loadUsers();
  const email = profile.emails[0].value;
  let user = users.find(u => u.username === email);

  if (!user) {
    // if not exist register
    user = {
      username: email,
      googleId: profile.id,
      fromGoogle: true
    };
    users.push(user);
    saveUsers(users);
    console.log(`Google user registered: ${email}`);
  }

  return done(null, user);
}));


(async () => {
  try {
    const googleIssuer = await Issuer.discover('https://accounts.google.com'); //to get the config used by google
    
    const client = new googleIssuer.Client({ //from .env
      client_id: process.env.OIDC_CLIENT_ID,
      client_secret: process.env.OIDC_CLIENT_SECRET,
      redirect_uris: [process.env.OIDC_CALLBACK_URL],
      response_types: ['code']
    });

    passport.use('oidc', new OpenIDConnectStrategy({ client }, (tokenset, userinfo, done) => {
      if (!userinfo) {
        return done('No user info received');
      }
      return done(null, userinfo);
    }));

    console.log('OIDC strategy successfull');

  } catch (err) {
    console.error('Error setting up OIDC strategy:', err);
  }
})();


passport.use('local-radius', new LocalStrategy(
  {
    usernameField: 'username',  //input sent in login
    passwordField: 'password',
    session: false 
  },
  async (username, password, done) => {
    try {
      const client = new RadiusClient({
        host: '127.0.0.1', // nuestro FreeRADIUS local
        dictionaries: [file],
      });

      const response = await client.accessRequest({
        secret: 'testing123', // default radius secret
        attributes: [
          [attributes.USER_NAME, username],
          [attributes.USER_PASSWORD, password],
        ],
      });

      console.log('RADIUS response:', response);

      return done(null, { username });

    } catch (error) {
      console.error('RADIUS authentication failed:', error);
      return done(null, false, { message: 'Invalid credentials (RADIUS)' });
    }
  }
));





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

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'], state: true }) //true es CSRF protection
);

app.get('/oidc/login',
  passport.authenticate('oidc', { scope: 'openid email profile' })
);




/*
Protected paths
*/
app.get('/home',
  (req, res, next) => {
    if (req.isAuthenticated()) return next(); // by google
    passport.authenticate('jwtCookie', { session: false }, (err, user, info) => {
      if (err) return next(err);
      if (!user) return res.redirect('/login');
      req.user = user;
      next();
    })(req, res, next);
  },
  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'))
  }
);


app.get('/',
  passport.authenticate(
    'jwtCookie',
    { session: false, failureRedirect: '/login' }
  ),
  (req, res) => {
    res.redirect('/home')
  }
)
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    console.log('correct google authentication:', req.user);
    res.redirect('/home');
  }
);

app.get('/oidc/callback',
  passport.authenticate('oidc', { failureRedirect: '/login' }),
  (req, res) => {
    // compares user with db
    const users = loadUsers();
    const email = req.user.email;
    let user = users.find(u => u.username === email); //if in db
    if (!user) { //if new
      user = {
        username: email,
        fromOIDC: true
      };
      users.push(user);
      saveUsers(users);
      console.log(`OIDC user registered: ${email}`);
    }

    const jwtClaims = { //creation of JWT
      sub: email,
      iss: 'localhost',
      aud: 'localhost',
      exp: Math.floor(Date.now() / 1000) + 604800,
      role: 'user'
    };

    const token = jwt.sign(jwtClaims, jwtSecret);

    res.cookie('jwt', token, { httpOnly: true, secure: true });
    console.log(`OIDC login successful, JWT issued for: ${email}`);
    res.redirect('/home');
  }
);





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
app.post('/login-radius',
  passport.authenticate('local-radius', { failureRedirect: '/login', session: false }),
  (req, res) => {
    // add users to the json db (not necessary but usefull to see the users
    const users = loadUsers();
    const existingUser = users.find(u => u.username === req.user.username);

    if (!existingUser) {
      users.push({ username: req.user.username, fromRadius: true });
      saveUsers(users);
      console.log(`User saved from RADIUS login: ${req.user.username}`);
    }

    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost',
      aud: 'localhost',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 setmana
      role: 'user'
    };

    const token = jwt.sign(jwtClaims, jwtSecret);

    res.cookie('jwt', token, { httpOnly: true, secure: true });
    console.log(`RADIUS login successful, JWT issued for: ${req.user.username}`);
    res.redirect('/home');
  }
);





//errors
app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})



//initializatio 
https.createServer(options, app).listen(port, () => {
  console.log(`HTTPS server running at https://localhost:${port}`)
})
