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
    password:String,
    num:Number
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

    const user = new User({name:username,password:hash,num: 0})
    await user.save();

    res.cookie("token",token,{
        httpOnly:true,
        maxAge:3600000
    })
    res.redirect('/home')
})

app.get('/home',(req,res)=>{
    res.render("main")
})

function Auth(req,res,next){
    const token_check = req.cookies.token;
    if(!token_check){
        return res.status(401).send("Token not found")
    }
    try{
        const decoded = jwt.verify(token_check,process.env.SECRET_KEY)
        req.user = decoded
        next()
    }catch{
        res.redirect("/");
    }
}

app.get("/profile", Auth, async (req, res) => {
    try {
        const user = await User.findOne({ name: req.user.name });
        if (!user) return res.redirect("/");

        res.render("profile", { username: user.name });
    } catch {
        res.redirect("/");
    }
});

app.get('/logout',(req,res)=>{
    res.clearCookie("token")
    res.json({out:false})
})


app.get('/plus', Auth, async (req, res) => {
  try {
    const user = await User.findOne({ name: req.user.name });

    if (!user) {
      return res.status(404).json({ status: false, message: "User not found" });
    }

    user.num = (user.num || 0) + 1; // если num нет, то начнём с 0
    await user.save();              // сохраняем обновление в MongoDB

    res.json({ status: true, count: user.num });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: false, message: "Server error" });
  }
});

const PORT = process.env.PORT || 3000
app.listen(PORT,()=>{
    console.log("Server start work on http://localhost:3000/")
})