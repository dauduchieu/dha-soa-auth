const { Op } = require('sequelize');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const FormData = require('form-data');
const bcrypt = require('bcrypt');
const { connectRabbitMQ, publishMessage, consumeMessage } = require('./configs/mq.js');

const User = require('./models/User.js')

const JWT_SECRET = "heheeh";
const FILE_SERVICE_URL = "http://localhost:3004/files/upload";
const DB_USER_INFOR_SYNC_MQ = "soa_user_infor"

class Service {
    // Connect message to Rabbit MQ
    async connectToMQ() {
        await connectRabbitMQ(DB_USER_INFOR_SYNC_MQ);
    }

    async publishSyncUserDB(eventType, newUser) {
        const eventData = {
            type: eventType, 
            payload: {
                user_id: newUser.user_id,
                username: newUser.username,
                email: newUser.email,
                fullname: newUser.fullname,
                avatar_image_link: newUser.avatar_image_link,
                role: newUser.role,
                is_banned: newUser.is_banned
            }
        };

        await publishMessage(DB_USER_INFOR_SYNC_MQ, eventData);
    }

    // Check user existence 
    async checkUserExistence(username, email) {
        return await User.findOne({
            where: {
                [Op.or]: [
                    { username: username },
                    { email: email }
                ]
            }
        });
    };

    // Create user
    async createUser(username, password, email, fullname) {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = await User.create({
            username,
            password: hashedPassword,
            email, 
            fullname,
            role: 'MEMBER',
            is_banned: false
        });

        await this.publishSyncUserDB('USER_CREATED', newUser)

        return newUser;
    };

    // Find user by username or email
    async findUserByCredential(username_or_email) {
        return await User.findOne({
            where: {
                [Op.or]: [
                    { username: username_or_email },
                    { email: username_or_email }
                ]
            }
        });
    };

    // Validate password
    async validatePassword(inputPassword, storedPassword) {
        return await bcrypt.compare(inputPassword, storedPassword);
    };

    // Varify access token
    async verifyAccessToken(token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);

            const user = await User.findByPk(decoded.user_id);

            if (!user) {
                return null;
            }

            if (user.is_banned) {
                return "BANNED";
            }

            return decoded;

        } catch (error) {
            return null;
        }
    }

    // Varrify refesh token
    async verifyRefreshToken(refreshToken) {
        try {
            // Verify signature
            const decoded = jwt.verify(refreshToken, JWT_SECRET);
            
            // Check user existence 
            const user = await User.findByPk(decoded.user_id);
            
            if (!user) {
                throw new Error("User not found");
            }

            if (user.is_banned) {
                throw new Error("User is banned");
            }
            
            return user;
        } catch (error) {
            throw new Error("Invalid or Expired Refresh Token");
        }
    }

    // Gen token
    generateAuthTokens(user, isRefresh = false) {
        const payload = {
            user_id: user.user_id,
            username: user.username,
            email: user.email,
            role: user.role,
            is_banned: user.is_banned
        };

        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        if (isRefresh) {
            return { token };
        }

        const refresh_token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

        return { token, refresh_token };
    }
    
    // Verify google token
    async verifyGoogleToken(accessToken) {
        const url = `https://www.googleapis.com/oauth2/v1/userinfo?access_token=${accessToken}`;

        const res = await fetch(url);
        if (!res.ok) throw new Error("Invalid Google Access Token");

        const data = await res.json();
        return data;
    }

    // Create user by google infor  
    async handleGoogleLogin(googlePayload) {
        const email = googlePayload.email;
        const name = googlePayload.name;
        const picture = googlePayload.picture;

        let user = await User.findOne({ where: { email: email } });

        if (user) {
            if (user.is_banned) {
                throw new Error("User is banned");
            }
        } else {

            user = await User.create({
                email: email,
                fullname: name,
                avatar_image_link: picture,
                username: null, 
                password: null, 
                role: 'MEMBER',
                is_banned: false
            });

            await this.publishSyncUserDB('USER_CREATED', user)
        }

        return user;
    }

    // Upload avater to cloud
    async uploadAvatarToCloud(file) {
        try {
            const formData = new FormData();

            formData.append("files", file.buffer, file.originalname);

            const response = await axios.post(FILE_SERVICE_URL, formData, {
                headers: {
                    ...formData.getHeaders() 
                }
            });

            if (response.data && response.data.urls && response.data.urls.length > 0) {
                return response.data.urls[0];
            }
            return null;
        } catch (error) {
            console.error("Upload to File Service failed:", error.message);
            throw new Error("Failed to upload avatar");
        }
    }

    // Get a user
    async getUserById(userId) {
        return await User.findByPk(userId);
    }

    // Update user
    async updateUserProfile(userId, updateData) {
        const user = await User.findByPk(userId);
        if (!user) throw new Error("User not found");

        const { username, oldPassword, newPassword, fullname, avatarUrl } = updateData;

        // Handle username
        if (username) {
            // if (user.username) {
            //     throw new Error("Username has already been set and cannot be changed");
            // } 
            
            if (!user.username) { 
                const existingUser = await User.findOne({ 
                    where: { username: username } 
                });
                if (existingUser) throw new Error("Username already exists");
    
                user.username = username;
            }
        }

        // Handle password
        if (newPassword) {
            if (user.password) {
                if (!oldPassword) {
                    throw new Error("Old password is required");
                }
                
                const isMatch = await bcrypt.compare(oldPassword, user.password);
                if (!isMatch) {
                    throw new Error("Incorrect old password");
                }
            }
            
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
            user.password = hashedPassword;
        }

        if (fullname) user.fullname = fullname;
        if (avatarUrl) user.avatar_image_link = avatarUrl;

        await user.save();

        await this.publishSyncUserDB('USER_UPDATED', user);
        
        return user;
    }

    // Post a user by admin
    async createUserByAdmin(requesterId, userData) {
        const { username, email, password, fullname, role } = userData;

        const requester = await this.getUserById(requesterId);
        
        if (!requester) {
            throw new Error("REQUESTER_NOT_FOUND"); 
        }

        if (requester.role !== 'ADMIN') {
            throw new Error("FORBIDDEN_NOT_ADMIN");
        }

        const existingUser = await this.checkUserExistence(username, email);

        if (existingUser) {
            throw new Error("USER_ALREADY_EXISTS");
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = await User.create({
            username: username,
            email: email,
            password: hashedPassword,
            fullname: fullname,
            role: role || 'MEMBER'
        });

        await this.publishSyncUserDB('USER_CREATED', newUser)

        return newUser;
    }

    // Get users by filter
    async getUsersByFilter(requesterId, { search, page, filter }) {
        const requester = await User.findByPk(requesterId);
        
        if (!requester) {
            throw new Error("REQUESTER_NOT_FOUND");
        }
        if (requester.role !== 'ADMIN') {
            throw new Error("FORBIDDEN_NOT_ADMIN");
        }

        // Handle pagination
        const limit = 10;
        const offset = (page - 1) * limit;

        const whereCondition = {};

        // Handle search
        if (search) {
            whereCondition[Op.or] = [
                { username: { [Op.like]: `%${search}%` } },
                { email: { [Op.like]: `%${search}%` } },
                { fullname: { [Op.like]: `%${search}%` } }
            ];
        }

        // Handle filter
        if (filter && filter !== 'ALL') {
            whereCondition.role = filter;
        }

        const { count, rows } = await User.findAndCountAll({
            where: whereCondition, 
            limit: limit,
            offset: offset,
            order: [['createdAt', 'DESC']],
            attributes: { 
                exclude: ['password'] 
            }
        });

        return {
            users: rows,
            totalItems: count,
            limit: limit,
            currentPage: page
        };
    }

    // Get a user detail
    async getUserDetail(requesterId, targetUserId) {
        const requester = await User.findByPk(requesterId);

        if (!requester) {
            throw new Error("REQUESTER_NOT_FOUND");
        }
        if (requester.role !== 'ADMIN') {
            throw new Error("FORBIDDEN_NOT_ADMIN");
        }

        // Find user
        const targetUser = await User.findByPk(targetUserId, {
            attributes: { 
                exclude: ['password'] 
            }
        });

        // Check 404
        if (!targetUser) {
            throw new Error("USER_NOT_FOUND");
        }

        return targetUser;
    }

    // Update a user by admin
    async updateUser(requesterId, targetUserId, updateData) {
        const { username, email, fullname, role, avatar_image_link, is_banned } = updateData;

        const requester = await User.findByPk(requesterId);
        if (!requester || requester.role !== 'ADMIN') {
            throw new Error("FORBIDDEN_NOT_ADMIN");
        }

        // Find target user
        const targetUser = await User.findByPk(targetUserId);
        if (!targetUser) throw new Error("USER_NOT_FOUND");

        // Check Conflict
        if (username || email) {
            const conflictCheck = await User.findOne({
                where: {
                    [Op.and]: [
                        { user_id: { [Op.ne]: targetUserId } }, 
                        {
                            [Op.or]: [
                                username ? { username } : null,
                                email ? { email } : null
                            ].filter(Boolean)
                        }
                    ]
                }
            });
            if (conflictCheck) throw new Error("USER_ALREADY_EXISTS");
        }

        const payload = {};
        if (username) payload.username = username;
        if (email) payload.email = email;
        if (fullname) payload.fullname = fullname;
        if (role) payload.role = role;

        if (avatar_image_link) {
            payload.avatar_image_link = avatar_image_link;
        }

        if (is_banned !== undefined) {
            const isBannedBool = String(is_banned) === 'true';

            if (isBannedBool === true) {
                if (String(requesterId) === String(targetUserId)) { 
                    throw new Error("CANNOT_BAN_YOURSELF");
                }
                
                if (targetUser.role === 'ADMIN') {
                    throw new Error("CANNOT_BAN_ADMIN");
                }
                
                if (targetUser.is_banned) {
                    throw new Error("USER_ALREADY_BANNED");
                }
            }

            payload.is_banned = isBannedBool;
        }

        await targetUser.update(payload);

        await this.publishSyncUserDB('USER_UPDATED', targetUser)

        return await User.findByPk(targetUserId, {
            attributes: { exclude: ['password'] }
        });
    }
}

module.exports = new Service();