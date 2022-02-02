require('dotenv').config();  
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true }));

app.use(express.static("public"));

//set up/initialize  session
app.use(session
({
    secret : "My Secret is Sadaf.",
    resave : false,
    saveUninitialized : false
}));

//initialize passport
app.use(passport.initialize());

app.use(passport.session());

//url where mongoDB database is located.
mongoose.connect("mongodb+srv://admin-sadaf:2001SadafDB@cluster0.0cjns.mongodb.net/userDB", {useNewUrlParser : true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

//create schema
const userSchema = new mongoose.Schema  //object created from mongoose Schema class.
({
    email : String,
    password : String,
    googleId : String,
    secret : String
});

userSchema.plugin(passportLocalMongoose); //used to hash and salt password and save our users in mongodb database.
userSchema.plugin(findOrCreate);

//create model
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy()); //local strategy to authenticate users using their username and password.

passport.serializeUser(function(user, done)
{
    done(null, user.id);
});

passport.deserializeUser(function(id, done)
{
    User.findById(id, function(err, user)
    {
        done(err, user);
    });
});

passport.use(new GoogleStrategy
({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/joke-bank",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) 
  {
    // User.findOrCreate({ googleId: profile.id }, function (err, user) 
    // {
    //   return cb(err, user);
    // });
    User.findOne( {googleId : profile.id}, function( err, foundUser ){
        if( !err ){                                                          //Check for any errors
            if( foundUser ){                                          // Check for if we found any users
                return cb( null, foundUser );                  //Will return the foundUser
            }else {                                                        //Create a new User
                const newUser = new User({
                    googleId : profile.id
                });
                newUser.save( function( err ){
                    if(!err){
                        return cb(null, newUser);                //return newUser
                    }
                });
            }
        }else{
            console.log( err );
        }
    });
  }
));

app.get ("/", function(req,res)
{
    res.render("home");
});

app.get("/auth/google", 
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/joke-bank", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) 
  {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get ("/login", function(req,res)
{
    res.render("login");
});

app.get ("/register", function(req,res)
{
    res.render("register");
});

app.get("/secrets", function(req,res)
{
    User.find({"secret": {$ne : null}}, function(err, foundUsers)
    {
        if(err)
        {
            console.log(err);
        }
        else
        {
            if(foundUsers)
            {
                res.render("secrets", {usersWithSecrets : foundUsers} );
            }
        }
    });
});

app.get("/submit",function(req,res)
{
    if(req.isAuthenticated())
    {
        res.render("submit");
    }
    else
    {
        res.redirect("/login");
    }
});

app.post("/submit",function(req,res)
{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, function(err, foundUser )
    {
        if(err)
        {
            console.log(err);
        }
        else
        {
            if(foundUser)
            {
                foundUser.secret = submittedSecret;
                foundUser.save(function()
                {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.get("/logout", function(req,res)
{
    req.logout();
    res.redirect("/");
});

app.post("/register", function(req,res)
{
   User.register({username: req.body.username}, req.body.password, function(err, user)
   {
       if(err)
       {
           console.log(err);
           res.redirect("/register");
       }
       else
       {
           passport.authenticate("local")(req,res, function()
           {
               res.redirect("/secrets");
           });
       }
   });
});

//check whether we have the user with credentials that they put in.
app.post("/login", function(req,res)
{
    const user = new User
    ({
        username : req.body.username,
        password : req.body.password
    });
    req.login(user, function(err)
    {
        if(err)
        {
            console.log(err);
        }
        else
        {
            passport.authenticate("local")(req, res, function()
            {
                res.redirect("/secrets");
            });
        }
    });
});

app.listen(process.env.PORT || 3000, function()
{
    console.log("Express server listening on port %d in %s mode", this.address().port, app.settings.env);
});
