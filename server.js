const express = require("express")
const { default: mongoose } = require("mongoose")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const { urlencoded } = require("body-parser")
require("dotenv").config()
const cookieParser = require("cookie-parser")
const app = express()

app.use(express.json())
app.use(express.urlencoded({extends:true}))
app.set("view engine","ejs")
app.use(express.static("public"));
app.use(cookieParser());

mongoose.connect(process.env.DATABASE)
.then(() => console.log("MongoDB Connected..."))
.catch((err) => console.log(`ERROR:${err}`))

const userSchema = mongoose.Schema({
    name:String,
    password:String
})
const User = mongoose.model("User",userSchema)

app.get('/check',(req,res)=>{
    const cookie = req.cookies.token

    if(!cookie){
        return res.json({status:false})
    }

    try{
        const valid = jwt.verify(cookie,process.env.SECRET_KEY)
        res.json({status:true})
    }catch{
        res.json({status:false})
    }
})

app.get('/',(req,res)=>{
    res.render("regis")
})

app.post('/post',async (req,res)=>{
    const { username,password } = req.body;
    const user_find = await User.findOne({name:username})

    if(user_find){
        return res.send("Пользаватель есть")
    }

    const hash = await bcrypt.hash(password,10)
    const token = jwt.sign({name:username},process.env.SECRET_KEY,{expiresIn:"7d"})

    const user = new User({name:username,password:hash})
    await user.save();

    res.cookie("token",token,{
        httpOnly:true,
        maxAge:360000
    })
    res.redirect('/home')
})

app.get('/home',(req,res)=>{
    res.render("main")
})

app.get('/logout',(req,res)=>{
    res.clearCookie("token")
    res.json({out:false})
})

app.listen(3000,()=>{
    console.log("Server start work on http://localhost:3000/")
})