let express = require('express')
let router = express.Router()
let userController = require('../controllers/users')
let { RegisterValidator, validatedResult, ChangePasswordValidator } = require('../utils/validator')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
const fs = require('fs')
const path = require('path')
const { check } = require('express-validator')
const { checkLogin } = require('../utils/authHandler')

// Load private key for RS256
const privateKey = fs.readFileSync(path.join(__dirname, '../keys/private.key'), 'utf8')

router.post('/register', RegisterValidator, validatedResult, async function (req, res, next) {
    let { username, password, email } = req.body;
    try {
        let newUser = await userController.CreateAnUser(
            username, password, email, '69b2763ce64fe93ca6985b56'
        )
        res.status(201).json({
            message: "Register successfully",
            user: {
                _id: newUser._id,
                username: newUser.username,
                email: newUser.email,
                fullName: newUser.fullName,
                avatarUrl: newUser.avatarUrl,
                status: newUser.status,
                role: newUser.role
            }
        })
    } catch (error) {
        res.status(400).json({
            message: error.message
        })
    }
})

router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    
    if (!username || !password) {
        res.status(400).json({
            message: "Username and password are required"
        })
        return;
    }
    
    let user = await userController.FindUserByUsername(username);
    if (!user) {
        res.status(404).json({
            message: "thong tin dang nhap khong dung"
        })
        return;
    }
    if (!user.lockTime || user.lockTime < Date.now()) {
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save();
            let token = jwt.sign({
                id: user._id,
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '1h'
            })
            res.status(200).json({
                message: "Login successfully",
                token: token,
                user: {
                    _id: user._id,
                    username: user.username,
                    email: user.email,
                    fullName: user.fullName,
                    avatarUrl: user.avatarUrl,
                    role: user.role
                }
            })
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = new Date(Date.now() + 60 * 60 * 1000)
            }
            await user.save();
            res.status(404).json({
                message: "thong tin dang nhap khong dung"
            })
        }
    } else {
        res.status(403).json({
            message: "user dang bi ban"
        })
    }
})

router.get('/me', checkLogin, function (req, res, next) {
    res.status(200).json({
        message: "Get user info successfully",
        user: {
            _id: req.user._id,
            username: req.user.username,
            email: req.user.email,
            fullName: req.user.fullName,
            avatarUrl: req.user.avatarUrl,
            status: req.user.status,
            role: req.user.role,
            createdAt: req.user.createdAt,
            updatedAt: req.user.updatedAt
        }
    })
})

router.post('/changepassword', checkLogin, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    let { oldPassword, newPassword } = req.body;
    let result = await userController.ChangePassword(req.user._id, oldPassword, newPassword);
    
    if (result.success) {
        res.status(200).json({
            message: result.message
        })
    } else {
        res.status(400).json({
            message: result.message
        })
    }
})

module.exports = router;