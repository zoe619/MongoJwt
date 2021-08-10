const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const UserModel = require('./models/user')
const bcrypt = require('bcryptjs')
const Jwt = require('jsonwebtoken')

const JWT_SECRET = '949404MKMXKVNXMCNSK^$@*CNSSOAMVUEYHSNS';
mongoose.connect('mongodb://localhost:27017/authdb', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
})

const app = express();

app.use(express.json());

app.use('/', express.static(path.join(__dirname, 'static')))

// register user

app.post('/api/register', async(req, res) => {
    const body = req.body

    const { username, password: plainTextPassword } = req.body;

    if (!username || typeof username !== 'string') {
        return res.json({ status: 'error', error: 'Invalid username' })
    }
    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({ status: 'error', error: 'Invalid password' })
    }

    const password = await bcrypt.hash(plainTextPassword, 10);

    try {
        const response = await UserModel.create({
            username,
            password
        })
        console.log('User created well ', response)
    } catch (error) {
        console.log(JSON.stringify(error))
        if (error.code === 11000) {
            return res.json({ status: 'error', 'error': 'Duplicate keys' })
        } else {
            throw (error)
        }

    }
    return res.json({ status: 'ok' })
})

// login
app.post('/api/login', async(req, res) => {

    const { username, password } = req.body

    const user = await UserModel.findOne({ username }).lean()

    if (!user) {
        return res.json({ error: 'Invalid username/password', status: 'error' })
    }
    if (await bcrypt.compare(password, user.password)) {

        const token = Jwt.sign({
            id: user._id,
            username: user.username
        }, JWT_SECRET)

        return res.json({ status: 'ok', data: token })
    }

    return res.json({ status: 'error', error: 'Invalid username/password' })
})

// update password
app.post('/api/change-password', async(req, res) => {

    const { token, newpassword } = req.body
    try {
        const user = Jwt.verify(token, JWT_SECRET)

        const _id = user.id;

        const hashedPassword = await bcrypt.hash(newpassword, 10)
        await UserModel.updateOne({ _id }, {
                $set: {
                    password: hashedPassword
                }

            }

        )
        res.json({ status: 'ok' })
    } catch (error) {
        res.json({ status: 'error', error: 'Invalid token' })
        console.log('error changing')
    }

})

app.listen(9999, (res, req) => {
    console.log('server started');
})