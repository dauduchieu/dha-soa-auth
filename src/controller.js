const service = require('./service.js');

class Controller {
    
    // Connect MQ
    async connectMQ() {
        await service.connectToMQ();
    }

    async register(req, res) {
        try {
            const { username, password, email, fullname } = req.body;
    
            // Validate input
            if (!username || !password || !email) {
                return res.status(400).json({ message: "Missing required fields" });
            }
    
            // Check conflict
            const existingUser = await service.checkUserExistence(username, email);
            if (existingUser) {
                return res.status(409).json({ message: "Username or Email already exists" });
            }
    
            const newUser = await service.createUser(username, password, email, fullname);
    
            return res.status(201).json({
                username: newUser.username
            });
    
        } catch (error) {
            console.error("Register Error:", error);
            return res.status(500).json({ message: "Internal Server Error" });
        }
    }

    async login(req, res) {
        try {
            const { username_or_email, password } = req.body;
            
            // Validate input
            if (!username_or_email || !password) {
                return res.status(400).json({ message: "Missing username/email or password" });
            }
    
            // Find user
            const user = await service.findUserByCredential(username_or_email);

            if (!user) {
                return res.status(401).json({ message: "Invalid credentials" });
            }

            const isValidPassword = await service.validatePassword(password, user.password);

            if (!isValidPassword) {
                return res.status(401).json({ message: "Invalid credentials"});
            }

            if (user.is_banned) {
                return res.status(401).json({ message: "User is banned" });
            }
    
            // Generate tokens
            const tokens = service.generateAuthTokens(user);
    
            return res.status(200).json(tokens);

        } catch (error) {
            console.error("Login Error:", error);
            return res.status(500).json({ message: "Internal Server Error" });
        }
    }

    async verify(req, res) {
        try {
            const authHeader = req.headers['authorization'];
            
            if (!authHeader) {
                return res.status(401).json({ verified: false, message: "No token provided" });
            }
    
            const token = authHeader.split(' ')[1];
    
            // Call service
            const result = await service.verifyAccessToken(token);
    
            if (result === "BANNED") {
                return res.status(403).json({
                    verified: false,
                    message: "User is banned"
                });
            }

            if (!result) {
                return res.status(401).json({
                    verified: false,
                    message: "Unauthorized: Invalid or Expired Token"
                });
            }
    
            return res.status(200).json({
                verified: true,
                user_id: result.user_id,
                role: result.role,
                is_banned: result.is_banned
            });
    
        } catch (error) {
            console.error("Verify Error:", error);
            return res.status(500).json({ verified: false, message: "Internal Server Error" });
        }
    };

    async refreshToken(req, res) {
        try {
            const { refresh_token } = req.body;
    
            // Validate input
            if (!refresh_token) {
                return res.status(400).json({ message: "Missing refresh_token" });
            }
    
            // Verify token & get user
            let user;
            try {
                user = await service.verifyRefreshToken(refresh_token);
            } catch (error) {
                return res.status(401).json({ message: "Invalid or expired refresh token" });
            }
    
            // Generate tokens
            const newAccessToken = service.generateAuthTokens(user, true);
    
            return res.status(200).json(newAccessToken);
    
        } catch (error) {
            console.error("Refresh Token Error:", error);
            return res.status(500).json({ message: "Internal Server Error" });
        }
    };

    async googleLogin(req, res) {
        try {
            const { google_token } = req.body;

            // Validate Input
            if (!google_token) {
                return res.status(400).json({ message: "Missing google_token" });
            }
    
            // Verify token
            let googlePayload;
            try {
                googlePayload = await service.verifyGoogleToken(google_token);
            } catch (err) {
                return res.status(400).json({ message: "Invalid Google Token" });
            }
    
            const user = await service.handleGoogleLogin(googlePayload);
    
            // Generate token
            const tokens = service.generateAuthTokens(user);
            return res.status(200).json(tokens);
    
        } catch (error) {
            console.error("Google Login Error:", error);

            if (error.message === "User is banned") {
                return res.status(403).json({ 
                    message: "Your account has been banned. Please contact admin." 
                });
            }

            return res.status(500).json({ message: "Internal Server Error" });
        }
    }

    async getMe(req, res) {
        try {
            const userId = req.headers['x-user-id'];
    
            if (!userId) {
                return res.status(401).json({ message: "Unauthorized (Missing User ID header)" });
            }
    
            const user = await service.getUserById(userId);
    
            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }
    
            return res.status(200).json({
                username: user.username,
                email: user.email,
                fullname: user.fullname,
                role: user.role,
                avatar_image_link: user.avatar_image_link
            });
    
        } catch (error) {
            console.error("Get Me Error:", error);
            return res.status(500).json({ message: "Internal Server Error" });
        }
    };

    // PUT /auth/users/me
    async updateMe(req, res) {
        try {
            const userId = req.headers['x-user-id'];
            if (!userId) {
                return res.status(401).json({ message: "Unauthorized (Missing User ID)" });
            }
            
            const { username, "old_password": oldPassword, "new_password": newPassword, fullname } = req.body;
            
            // Handle upload file
            let cloudAvatarUrl = null;
            if (req.file) {
                try {
                    cloudAvatarUrl = await service.uploadAvatarToCloud(req.file);
                } catch (uploadError) {
                    console.error("Upload Error:", uploadError);
                    return res.status(502).json({ message: "Failed to upload avatar image" });
                }
            }
    
            // Call service
            const updatedUser = await service.updateUserProfile(userId, {
                username,
                oldPassword,
                newPassword,
                fullname,
                avatarUrl: cloudAvatarUrl 
            });
    
            return res.status(200).json({
                username: updatedUser.username,
                email: updatedUser.email,
                fullname: updatedUser.fullname,
                role: updatedUser.role,
                avatar_image_link: updatedUser.avatar_image_link
            });
    
        } catch (error) {
            console.error("Update Me Error:", error.message);

            if (error.message === "User not found") {
                return res.status(404).json({ message: error.message });
            }

            if (error.message === "Username already exists") {
                return res.status(409).json({ message: error.message });
            }

            if (error.message.includes("password")) {
                return res.status(400).json({ message: error.message });
            } 

            if (error.message === "Username has already been set and cannot be changed") {
                return res.status(403).json({ message: error.message });
            }

            return res.status(500).json({ message: "Internal Server Error" });
        }
    };

    // ------FOR ADMIN------
    // Create user by admin
    async createUserByAdmin(req, res) {
        try {
            const requesterId = req.header("x-user-id");
            
            const { username, email, password, fullname, role } = req.body;

            // Validate input
            if (!username || !email || !password || !fullname) {
                return res.status(400).json({ message: "Missing required fields" });
            }

            const newUser = await service.createUserByAdmin(requesterId, {
                username,
                email,
                password,
                fullname,
                role
            });

            return res.status(201).json({
                username: newUser.username
            });

        } catch (error) {
            console.error("Create User Error:", error.message);

            if (error.message === "FORBIDDEN_NOT_ADMIN") {
                return res.status(403).json({ message: "Forbidden: Only Admin can create users" });
            }
            if (error.message === "USER_ALREADY_EXISTS") {
                return res.status(409).json({ message: "Conflict: Username or Email already exists" });
            }
            if (error.message === "REQUESTER_NOT_FOUND") {
                return res.status(401).json({ message: "Unauthorized: Requester profile not found" });
            }

            return res.status(500).json({ message: "Internal Server Error" });
        }
    }

    // Get users
    async getUsers(req, res) {
        try {
            const requesterId = req.header("x-user-id");
            
            const { search, page, filter } = req.query; 
            
            const pageInt = parseInt(page) || 1;
            const filterStr = filter || 'ALL';

            // Call service
            const data = await service.getUsersByFilter(requesterId, {
                search: search,
                page: pageInt,
                filter: filterStr 
            });

            return res.status(200).json({
                users: data.users,
                meta: {
                    total_items: data.totalItems,
                    page_size: data.limit,
                    current_page: data.currentPage,
                    total_pages: Math.ceil(data.totalItems / data.limit)
                }
            });

        } catch (error) {
            console.error("Get Users Error:", error.message);

            if (error.message === "FORBIDDEN_NOT_ADMIN") {
                return res.status(403).json({ message: "Forbidden: Admin access required" });
            }
            if (error.message === "REQUESTER_NOT_FOUND") {
                return res.status(401).json({ message: "Unauthorized: Requester not found" });
            }

            return res.status(500).json({ message: "Internal Server Error" });
        }
    }

    // Get a user detail
    async getUserDetail(req, res) {
        try {
            const requesterId = req.header("x-user-id");
            
            const { id } = req.params;  

            // Call service
            const user = await service.getUserDetail(requesterId, id);

            return res.status(200).json(user);
        } catch (error) {
            console.error("Get User Detail Error:", error.message);

            if (error.message === "FORBIDDEN_NOT_ADMIN") {
                return res.status(403).json({ message: "Forbidden: Admin access required" });
            }
            if (error.message === "USER_NOT_FOUND") {
                return res.status(404).json({ message: "User not found" });
            }
            if (error.message === "REQUESTER_NOT_FOUND") {
                return res.status(401).json({ message: "Unauthorized: Requester not found" });
            }

            return res.status(500).json({ message: "Internal Server Error" });
        }
    }

    // Update a user by admin
    async updateUserByAdmin(req, res) {
        try {
            const requesterId = req.header("x-user-id");
            const targetUserId = req.params.id;
            
            const { username, email, fullname, role, is_banned } = req.body;

            let cloudAvatarUrl = undefined; 

            if (req.file) {
                try {
                    cloudAvatarUrl = await service.uploadAvatarToCloud(req.file);
                } catch (uploadError) {
                    return res.status(502).json({ message: "Failed to upload avatar image" });
                }
            }

            // Call service
            const updatedUser = await service.updateUser(requesterId, targetUserId, {
                username, 
                email, 
                fullname, 
                role, 
                avatar_image_link: cloudAvatarUrl, 
                is_banned
            });

            return res.status(200).json(updatedUser);

        } catch (error) {
            console.error("Update User Admin Error:", error.message);

            if (error.message === "FORBIDDEN_NOT_ADMIN") {
                return res.status(403).json({ message: "Forbidden: Only Admin can update users" });
            }
            if (error.message === "USER_NOT_FOUND") {
                return res.status(404).json({ message: "User not found" });
            }
            if (error.message === "USER_ALREADY_EXISTS") {
                return res.status(409).json({ message: "Conflict: Username or Email already exists" });
            }
            if (error.name === 'SequelizeValidationError') {
                 return res.status(400).json({ message: error.message });
            }
            if (error.message === "CANNOT_BAN_ADMIN") {
                return res.status(403).json({ message: "Forbidden: You cannot ban another Admin" });
            }
            if (error.message === "CANNOT_BAN_YOURSELF") {
                return res.status(400).json({ message: "You cannot ban yourself" });
            }
            if (error.message === "USER_ALREADY_BANNED") {
                return res.status(409).json({ message: "User is already banned" });
            }
            return res.status(500).json({ message: "Internal Server Error" });
        }
    }
}

module.exports = new Controller();