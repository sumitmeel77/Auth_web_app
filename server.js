const bodyParser = require("body-parser")
const express = require("express")
const path = require("path")
const mongoose = require('mongoose')
const User = require("./model/user.js")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser");
const { error } = require("console")

const port = process.env.PORT || 8000;

// const { MongoClient } = require('mongodb');

const db = "mongodb+srv://AuthApp:AuthApp@cluster0.5kzz4.mongodb.net/myFirstDatabase?retryWrites=true&w=majority";
// const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
// client.connect(err => {
//     const collection = client.db("test").collection("devices");
//     // perform actions on the collection object
//     client.close();
// });

// secret key to jwt token
const jwt_sceret = 'hsdfgshkagfahjsgfkhg3624@!3j234bk'

// connecting with mongoose
mongoose.connect(db, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => { console.log("connection successfull") }).catch((err) => console.log(err))

const app = express()

app.use(cookieParser());

app.use("/", express.static(path.join(__dirname, 'static')))

app.use(express.json());  // for application json parser


//Adding data on server side from web app
//registering the user
app.post("/api/register", async (req, res) => {

    const { username, password: plainTextPassword } = req.body

    //verifying the correctness of password
    if (!username || typeof username !== 'string') {
        return res.json({ status: 'error', error: 'Invalid username' })
    }

    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({ status: 'error', error: 'Invalid password' })
    }

    if (plainTextPassword.length < 5) {
        return res.json({
            status: 'error',
            error: 'Password too small. Should be atleast 6 characters'
        })
    }

    const password = await bcrypt.hash(plainTextPassword, 10) // Hashing the password

    // Adding data to database
    try {
        const response = await User.create({
            username,
            password
        })
        // console.log('User created successfully: ', response)
    } catch (error) {
        if (error.code === 11000) {
            // duplicate username
            return res.json({ status: 'error', error: 'Username already in use' })
        }
        throw error
    }

    res.json({ status: "ok" })

})

//Acccessing data from server side on web app
// Adding login
app.post("/api/login", async (req, res) => {

    //checking whether username and password are correct or not
    const { username, password } = req.body
    // first searching the username and then checking whether password is correct or not
    const user = await User.findOne({ username }).lean()

    if (!user) {
        return res.json({ status: 'error', error: 'Invalid username/password' })
    }

    if (await bcrypt.compare(password, user.password)) {

        //generating jwt token for authentication
        const token = jwt.sign(
            {
                id: user._id,
                username: user.username
            },
            jwt_sceret //  a scret key attached with every token
        )

        //pushing new token every time user login through different browser
        await User.findOneAndUpdate(
            { username: user.username },
            { $push: { tokens: [{ "tokenvalue": token }] } }
        )
        //updating cookie value
        res.cookie("jwt", token)

        return res.json({ status: "ok", data: token })
    }

    res.json({ status: 'error', error: 'Invalid username/password' })
})

// changing the password
app.post("/api/change-password", async (req, res) => {
    const { token, newpassword: plainTextPassword } = req.body // it will return body of token

    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({ status: 'error', error: 'invalid password' })
    }

    if (plainTextPassword.length < 5) {
        return res.json({
            status: 'error',
            error: 'Password too small. Should be atleast 6 characters'
        })
    }

    try {
        const user = jwt.verify(token, jwt_sceret) // verifying user with jwt token

        const _id = user.id

        const password = await bcrypt.hash(plainTextPassword, 10)
        //updating password
        await User.updateOne(
            { _id },
            {
                $set: { password }
            }
        )
        //deleting all tokens for a user
        await User.updateOne(
            { _id },

            { $set: { tokens: [] } }
        )
        //add preent token of a website
        await User.updateOne(
            { _id },
            { $push: { tokens: [{ "tokenvalue": token }] } }
        )

        res.json({ status: 'ok' })
    } catch (error) {
        // console.log(error)
        res.json({ status: 'error', error: ';))' })
    }
})

//api for logout button
app.get("/logout", async (req, res) => {
    try {
        const cookieData = req.cookies.jwt
        res.clearCookie("jwt")
        // searching user name using value of stored cookie on browser
        const user = await User.findOne({ tokens: { $elemMatch: { tokenvalue: cookieData } } })
        //deleting token of user from browser
        await User.findOneAndUpdate(
            { username: user.username },
            { $pull: { tokens: { tokenvalue: cookieData } } }
        )
        res.sendFile(__dirname + "/static/index.html");
    } catch (error) {
        res.json({ status: error })
    }
})

//api for verifying user
app.get("/userData", async (req, res) => {
    try {
        const cookievalue = req.cookies.jwt
        // res.clearCookie("jwt")
        // searching user name using value of stored cookie on browser
        const a = await User.findOne({ tokens: { $elemMatch: { tokenvalue: cookievalue } } })
        if (a != null) { res.json({ status: "found" }) } else { res.json({ status: "notfound" }) }
    } catch (error) {
        res.json({ status: "notfound" })
    }
})


app.listen(port, () => {
    console.log(`server at ${port}`)
}
)