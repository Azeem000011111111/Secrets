require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption")


const app = express();


// Set the view engine to ejs
app.set("view engine", "ejs");

// Use body-parser to parse the request body
app.use(bodyParser.urlencoded({ extended: true }));

// Use express.static to serve static files from the public directory
app.use(express.static("public"));

mongoose.connect("mongodb://127.0.0.1:27017/userDB");


const userSchema= new mongoose.Schema ({
    email:String,
    password:String
});


userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]})

const User =new mongoose.model("User",userSchema);








app.get("/", async function(req, res){
    res.render("home")
})


app.get("/login", async function(req, res){
    res.render("login")
})



app.get("/register", async function(req, res){
    res.render("register")
})

app.post("/register", async function(req, res){
    const newUser = new User({
        email:req.body.username,
        password:req.body.password,
    })
    try{
        newUser.save()
        res.render("secrets")
    }catch (error){
        console.log(error)
    }
})
app.post("/login", async function (req, res) {
    const username = req.body.username;
    const password = req.body.password;

    const foundUser = await User.findOne({ email: username });

    if (foundUser) {
        if (foundUser.password === password) {
            res.render("secrets");
        }
    } else {
        res.render("login");
    }
});

app.listen(3000, function (){
    console.log("server started")
})