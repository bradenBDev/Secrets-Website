require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook");
const findOrCreate = require("mongoose-findorcreate");


// Initialize Express
const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false,
}));

// Set Express to use passport
app.use(passport.initialize());
app.use(passport.session());

// Set up Mongoose
mongoose.connect(process.env.MONGO_DB_URL, { useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

// Set up passport
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

// Describe the Google login strategy
passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

// Describe the Facebook login strategy
passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id, googleId: null }, function (err, user) {
            return cb(err, user);
        });
    }
));


// Home route

app.get("/", function (req, res) {
    // If user is already logged in, redirect to /secrets
    if (req.user) {
        res.redirect('/secrets')
    } else {
        res.render('home')
    }
});


// Google's login redirects. They use passport to authenticate the user.

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect secrets.
        res.redirect("/secrets");
    });


// Facebook's login redirects. They use passport to authenticate the user.

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });


// The route that returns the list of secrets. Renders the secrets.ejs
// page with the foundSecrets list.

app.get("/secrets", function (req, res) {
    User.find({secret: {$ne: null}}, function (err, foundSecrets) {
        if (err) {
            console.log(err);
        } else if (foundSecrets) {
            res.render("secrets", {usersWithSecrets: foundSecrets});
        }
    });
});


// The submit route, returns the submit.ejs page if the user is logged in,
// and adds a secret to the database if the request is POST.

app.route("/submit")

    .get(function (req, res) {

        if (req.isAuthenticated()) {
            res.render("submit");
        } else {
            res.redirect("/login");
        }
    })

    .post(function (req, res) {

        const submittedSecret = req.body.secret;

        User.findById(req.user.id, function (err, foundUser) {
            if (err) {
                console.log(err);
            } else if (foundUser) {

                // Add a secret to the found user's object, then save it and
                // redirect to the /secrets page.
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets");
                });
            }
        });
    });


// Logout route

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
});


// Register the user. Returns register.ejs if the request is GET, and adds the
// user to the database if they don't exist. If they do exist, then the user
// is logged in.

app.route("/register")

    .get(function (req, res) {
        res.render("register");
    })

    .post(function (req, res) {
        User.register({username: req.body.username}, req.body.password, function (err, user) {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                });
            }
        });
    });


// Logs the user in. Returns login.ejs if the request is GET, attempts to
// authenticate the user when the request is POST.

app.route("/login")

    .get(function (req, res) {
        res.render("login");
    })

    .post(function (req, res) {
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


// Spin up the server

app.listen(process.env.PORT || 3000, function () {
    console.log("Server started on port 3000.");
});