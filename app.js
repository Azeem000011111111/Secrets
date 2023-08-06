require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const { hash } = require("bcrypt");
const saltRounds = 10;
const expess_session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(expess_session({
    secret: "Our little Secret",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secrets: [String]
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id).exec()
        .then(user => {
            if (user) {
                user.googleId = user.googleId || null; // Ensure googleId exists and set it to null if not present
                done(null, user);
            } else {
                done(null, null);
            }
        })
        .catch(err => {
            done(err, null);
        });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    async function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, {
            googleId: profile.id,
            email: profile.email,
            password: await bcrypt.hash(profile.id, saltRounds)
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    async function (req, res) {
        // Successful authentication, save Google ID to the database
        const googleId = req.user.googleId;
        if (googleId) {
            try {
                const foundUser = await User.findById(req.user._id);
                if (foundUser) {
                    foundUser.googleId = googleId;
                    await foundUser.save();
                    res.redirect('/secrets');
                } else {
                    console.log("Error finding user in the database");
                    res.redirect('/secrets');
                }
            } catch (err) {
                console.log("Error saving Google ID to the database:", err);
                res.redirect('/secrets');
            }
        } else {
            res.redirect('/secrets');
        }
    }
);

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", async function (req, res) {
    try {
        if (req.isAuthenticated()) {
            const foundUsers = await User.find({ "secret": { $ne: null } }).exec();
            res.render("secrets", { usersWithSecret: foundUsers });
        } else {
            res.redirect("/login");
        }
    } catch (err) {
        console.log(err);
        res.redirect("/login");
    }
});

// ... Existing code ...

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", async function (req, res) {
    const submittedSecret = req.body.secret;
    try {
        // Find the user by ID
        const foundUser = await User.findById(req.user._id);

        if (foundUser) {
            // Add the new secret to the user's secrets array
            foundUser.secrets.push(submittedSecret);

            // Save the updated user document
            await foundUser.save();

            // Redirect to the secrets page
            res.redirect("/secrets");
        } else {
            console.log("User not found.");
            res.redirect("/secrets");
        }
    } catch (err) {
        console.log("Error saving secret:", err);
        res.redirect("/secrets");
    }
});




app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
});

app.post("/register", function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
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

app.post("/login", function (req, res) {
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

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});