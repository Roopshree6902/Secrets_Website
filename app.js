require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
// const encrypt=require("mongoose-encryption");
// const md5=require("md5");
// const bcrypt = require("bcryptjs");
// const salt = bcrypt.genSaltSync(10);
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy=require("passport-facebook").Strategy;
const findOrCreate=require("mongoose-findorcreate");

const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret:"Our little secret.",
  resave:false,
  saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});
mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
  Email: String,
  Password: String,
  googleId:String,
  facebookId:String,
  secret:String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

///for encryption plugin/////
// userSchema.plugin(encrypt, { secret: process.env.SECR,encryptedFields:["Password"] });

const User = mongoose.model("User", userSchema);
// order is impostant//
passport.use(User.createStrategy());
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
  clientID:     process.env.CLINT_ID,
  clientSecret: process.env.CLINT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileUrl:"http://www.googleapis.com/oauth2/v3/userinfo",
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res) {
  res.render("home");
});


app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res) {
  res.render("login");
});
app.get("/register", function(req, res) {
  res.render("register");
});
app.get("/secrets", function(req, res) {
  User.find({"secret":{$ne:null}},function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        res.render("secrets",{userWithSecrets:foundUser});
      }
    }
  });
});
app.get("/submit", function(req, res) {
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});
app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});


app.post("/register", function(req, res) {
  User.register({username:req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });

  ///////////////bcryption/////////////
  // bcrypt.hash(req.body.password, 8, function(err, hash) {
  //   const newUser = new User({
  //     Email: req.body.username,
  //     Password: hash
  //   });
  //   newUser.save(function(err) {
  //     if (!err) {
  //       res.render("secrets");
  //     } else {
  //       console.log(err);
  //     }
  //   });
  //
  // });
  ///////////for hashing///////////////////////
  // const newUser=new User({
  //   Email:req.body.username,
  //   Password:md5(req.body.password)
  // });
  // newUser.save(function(err){
  //   if(!err){
  //     res.render("secrets");
  //   }else{
  //     console.log(err);
  //   }
  // });
});

app.post("/login", function(req, res) {
  const user=new User({
      Email:req.body.username,
      Password:req.body.Password
  });

  req.login(user,function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
    });
  }});

  // const username = req.body.username;
  // // const password=md5(req.body.password);
  // const password = req.body.password;
  // User.findOne({
  //   Email: username
  // }, function(err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       ////////////bcryption///////
  //       bcrypt.compare(req.body.password, foundUser.Password, function(err, result) {
  //         if (result === true) {
  //           res.render("secrets");
  //         }
  //       });
  //       /////for hasing////////////////////////
  //       // if(foundUser.Password===password){
  //       //   res.render("secrets");
  //       // }else{
  //       //   res.send("Password doesn't match!");
  //       // }
  //     }
  //   }
  // });
});
app.post("/submit",function(req,res){
  const submittedSecret=req.body.secret;
  console.log(req.user.id);
  User.findById(req.user.id,function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret=submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});



app.listen(3000, function() {
  console.log("Server started on port 3000");
});
