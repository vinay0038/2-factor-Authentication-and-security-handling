import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import nodemailer from "nodemailer";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

let transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // Your email
    pass: process.env.EMAIL_PASS
  }
});

let otpStore = {}; // Store OTPs temporarily
let tempUserStore = {}; // Temporary store for user data

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // Generates a 6-digit OTP
}

function sendOTP(email, otp) {
  console.log('Sending OTP to:', email); // Debugging log
  console.log('Generated OTP:', otp); // Debugging log

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}`,
    html: `<p>Your OTP code is <b>${otp}</b></p>`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return console.log('Error:', error);
    }
    console.log('OTP sent: %s', info.messageId);
  });
}

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/otp-page", (req, res) => {
  const email = req.query.email;
  if (email) {
    res.render("otp-page.ejs", { email });
  } else {
    res.redirect("/register");
  }
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query(
        `SELECT secret FROM users WHERE email = $1`,
        [req.user.email]
      );
      const secret = result.rows[0].secret;
      if (secret) {
        res.render("secrets.ejs", { secret: secret });
      } else {
        res.render("secrets.ejs", { secret: "Enter Your Secrets" });
      }
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const otp = generateOTP();
          otpStore[email] = otp; // Save OTP to verify later
          tempUserStore[email] = { email, hash }; // Temporarily store user data
          sendOTP(email, otp);
          console.log("OTP sent to:", email); // Debugging log
          res.redirect(`/otp-page?email=${encodeURIComponent(email)}`);
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (otpStore[email] === otp) {
    try {
      const userData = tempUserStore[email];
      if (userData) {
        const result = await db.query(
          "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
          [userData.email, userData.hash]
        );
        delete otpStore[email]; // OTP verified, remove from store
        delete tempUserStore[email]; // Remove temporary user data
        req.login(result.rows[0], (err) => {
          if (err) {
            console.error("Error logging in user:", err);
            res.redirect("/login");
          } else {
            res.redirect("/secrets");
          }
        });
      } else {
        res.status(400).send('User data not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).send('Server error');
    }
  } else {
    res.status(400).send('Invalid OTP');
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      passReqToCallback: true,
    },
    async function (request, accessToken, refreshToken, profile, done) {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.emails[0].value,
        ]);
        if (result.rows.length === 0) {
          const newUser = {
            email: profile.emails[0].value,
            googleId: profile.id,
          };
          const insertResult = await db.query(
            "INSERT INTO users (email, google_id) VALUES ($1, $2) RETURNING *",
            [newUser.email, newUser.googleId]
          );
          return done(null, insertResult.rows[0]);
        } else {
          return done(null, result.rows[0]);
        }
      } catch (err) {
        console.log(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.email);
});

passport.deserializeUser(async (email, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rows.length > 0) {
      done(null, result.rows[0]);
    } else {
      done(new Error("User not found"));
    }
  } catch (err) {
    done(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/submit", async (req, res) => {
  const secret = req.body.secret;
  try {
    await db.query("UPDATE users SET secret = $1 WHERE email = $2", [
      secret,
      req.user.email,
    ]);
    res.redirect("/secrets");
  } catch (err) {
    console.log(err);
  }
});

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
