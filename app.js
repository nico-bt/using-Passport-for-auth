require('dotenv').config()
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const User = require("./model")
const bcrypt = require("bcrypt")

// Conect MongoDb
const mongoDb = process.env.MONGO_CONNECTION;
mongoose.connect(mongoDb, { 
    dbName: "using-Passport", 
    useUnifiedTopology: true, 
    useNewUrlParser: true 
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

// Express and view engine
const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");


// Passport Config
// ----------------------------------------------------------------------------------------------------

// Setting up the Local Strategy
passport.use(
    new LocalStrategy((username, password, done) => {
      User.findOne({ username: username }, (err, user) => {
        if (err) { 
          return done(err);
        }
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        }
        // Hash password to compare
        bcrypt.compare(password, user.password, function(err, result) {
            if (result) {
                // User exists in db and password match. Log user in:
                return done(null, user);
            } else{
                return done(null, false, { message: "Incorrect password" });
            }
        });
      });
    })
  );

// Sessions and serialization
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
});


// Middleware
app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// req.user is added by Passport. With this middleware, we pass the current user to all the views
// app.use(function(req, res, next) {
//     res.locals.user = req.user;
//     next();
// });

// Custom middleware for checking auth
const reqAuth = (req, res, next) =>{
    if(req.isAuthenticated()){
        next()
    }else{
        return res.send("<h1>You are NOT authorized.</h1>")
    }
}

// Routes
// ----------------------------------------------------------------------------------------------------
app.get("/", (req, res) => { 
    res.render("index", {user: req.user})
});

app.get("/sign-up", (req, res) => {
    res.render("sign-up-form")
});

app.post("/sign-up", async (req, res, next) => {
    const {username, password} = req.body
    if(!username || !password) {
        return res.redirect("/sign-up")
    }
    try {
        bcrypt.hash(password, 10, async function(err, hash) {
            if(err){
                console.log(err)
            }
            // Store hash in your password DB.
            const user = await User.create({username, password: hash})
            
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/");
            })
        });
    } catch (error) {
        console.log(error)
    }
});

// LOG IN with PASSPORT:
// Call passport.authenticate(). 
// This middleware looks at the request body for parameters named "username" and "password" 
// then runs the LocalStrategy function that we defined earlier to see if the username and password are in the database. 
// It then creates a session cookie that gets stored in the user’s browser, and that we can access in all future requests 
// to see whether or not that user is logged in.
// if there is an user, it adds that user to the request object for us. 
// So, all we need to do is check for --> req.user 

app.post("/log-in", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  }));

app.get("/log-out",(req, res)=>{
    req.logout((err) => {
        if (err) {
          return next(err);
        }
        res.redirect("/");
      });
})

app.get("/protected", reqAuth, (req, res)=>{
    res.send("<h1>This is a protected Route. Kewl!</h1>")
})

app.listen(3000, () => console.log("app listening on port 3000!"));