let jwt = require('jsonwebtoken')
let userController = require("../controllers/users")
const fs = require('fs')
const path = require('path')

// Load public key for RS256 verification
const publicKey = fs.readFileSync(path.join(__dirname, '../keys/public.key'), 'utf8')

module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token || !token.startsWith('Bearer ')) {
                res.status(401).json({ message: "ban chua dang nhap" })
                return;
            }
            token = token.split(" ")[1];
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            let user = await userController.FindUserById(result.id);
            if (user) {
                req.user = user
                next()
            } else {
                res.status(401).json({ message: "ban chua dang nhap" })
            }
        } catch (error) {
            res.status(401).json({ message: "ban chua dang nhap" })
        }
    }
}