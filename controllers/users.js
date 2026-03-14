let userModel = require('../schemas/users')
let bcrypt = require('bcrypt')
module.exports = {
    CreateAnUser: async function (
        username, password, email, role, fullname, avatarUrl, status, loginCount) {
        let newUser = new userModel({
            username: username,
            password: password,
            email: email,
            fullName: fullname,
            avatarUrl: avatarUrl,
            status: status,
            role: role,
            loginCount: loginCount
        });
        await newUser.save();
        return newUser;
    },
    FindUserByUsername: async function (username) {
        return await userModel.findOne({
            username: username,
            isDeleted: false
        })
    },
    FindUserById: async function (id) {
        try {
            return await userModel.findOne({
                _id: id,
                isDeleted: false
            })
        } catch (error) {
            return false
        }
    },
    ChangePassword: async function (userId, oldPassword, newPassword) {
        try {
            let user = await userModel.findOne({
                _id: userId,
                isDeleted: false
            });
            
            if (!user) {
                return {
                    success: false,
                    message: "User not found"
                };
            }
            
            // Verify old password
            if (!bcrypt.compareSync(oldPassword, user.password)) {
                return {
                    success: false,
                    message: "Old password is incorrect"
                };
            }
            
            // Update password
            user.password = newPassword;
            await user.save();
            
            return {
                success: true,
                message: "Password changed successfully"
            };
        } catch (error) {
            return {
                success: false,
                message: error.message
            };
        }
    }
}