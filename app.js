/**
 * Google Auth
**/

// Import modules
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require("passport-local-mongoose");
// NOTE: passport-local-mongoose contains "passport-local" so we don't need to explicitly require it here
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

// Setup express app
const app = express();
const port = 3000;

// Run middleware
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

// initalize session
app.use(session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false
}))

// initalize passport : set to expire when browser session ends
app.use(passport.initialize());
// tell passport to use the session we just initalized above
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" // Google+ deprecated, use Google userinfo endpoint instead
  },
  // Note: there is no Mongoose method findOrCreate by default--Passport requires that we create that function ourselves
  // We can install the mongoose-findorcreate package
  function(accessToken, refreshToken, profile, cb) {
    // log the profile of the user
    console.log(profile);

    // basically, when a user clicks on the Google button to authenticate themselves using Google, 
    // regardless of whether they were logging in or signing up, we will either create a new account based on that Google User's profile,
    // or login to an existing local account; find or create
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Connect to MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set('useCreateIndex', true);

// Setup Mongoose Schema
const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String
});

// add passport-local-mongoose as a plugin to our userSchema; this is what implements hashing & salting
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate); // add findOrCreate method

// Setup Mongoose Models
const User = new mongoose.model("User", userSchema);

// create user strategy
passport.use(User.createStrategy());
// serialize users: works for both local authentication and 3rd-party authentication
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

app.get("/", function (req, res) {
    res.render("home");
});

// Direct user to Google Authentication Sign up Page (on Google)
app.get("/auth/google", 
    passport.authenticate('google', { scope: ['profile'] 
}));
// Google redirects them back to us... we need to authenticate them locally now
app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", function (req, res) {
    req.logout(function () {
        res.redirect("/");
    });
});

app.post("/register", function (req, res) {
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) { 
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    }); 
});

app.post("/login", async function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

// Run App
app.listen(port, function() {
    console.log(`Server started on port ${port}.`);
});

