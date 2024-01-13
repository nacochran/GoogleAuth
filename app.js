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

// Connect to MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set('useCreateIndex', true);

// Setup Mongoose Schema
const userSchema = new mongoose.Schema ({
    email: String,
    password: String
});

// add passport-local-mongoose as a plugin to our userSchema; this is what implements hashing & salting
userSchema.plugin(passportLocalMongoose);

// Setup Mongoose Models
const User = new mongoose.model("User", userSchema);

// create user strategy
passport.use(User.createStrategy());
// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function (req, res) {
    res.render("home");
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
    req.logout();
    res.redirect("/");
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

