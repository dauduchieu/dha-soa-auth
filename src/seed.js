// services/auth-service/seed_auth.js
const bcrypt = require('bcrypt');
const sequelize = require('./configs/database'); // Đảm bảo đường dẫn đúng tới file config db của bạn
const User = require('./models/User'); // Đảm bảo đường dẫn đúng tới model User

const seedAuth = async () => {
    try {
        // Kết nối và đồng bộ model (force: true sẽ xóa bảng cũ nếu có)
        await sequelize.authenticate();
        console.log('🔌 Auth DB Connected.');
        await User.sync({ force: true });
        console.log('⚠️ User table reset.');

        const saltRounds = 10;
        const passwordHash = await bcrypt.hash('123456', saltRounds);

        // Danh sách user mẫu (Cố định ID để khớp với Forum Service)
        const users = [
            {
                user_id: 1,
                username: 'admin_user',
                email: 'admin@uet.vnu.edu.vn',
                password: passwordHash,
                fullname: 'Admin Quản Trị',
                avatar_image_link: 'https://ui-avatars.com/api/?name=Admin&background=ef4444&color=fff',
                role: 'ADMIN',
                is_banned: false
            },
            {
                user_id: 2,
                username: 'nguyenvana',
                email: 'nguyenvana@gmail.com',
                password: passwordHash,
                fullname: 'Nguyễn Văn A',
                avatar_image_link: 'https://ui-avatars.com/api/?name=Nguyen+A&background=0D8ABC&color=fff',
                role: 'MEMBER',
                is_banned: false
            },
            {
                user_id: 3,
                username: 'lethib',
                email: 'lethib@gmail.com',
                password: passwordHash,
                fullname: 'Lê Thị B',
                avatar_image_link: 'https://ui-avatars.com/api/?name=Le+B&background=random',
                role: 'MEMBER',
                is_banned: false
            },
            {
                user_id: 4,
                username: 'banned_guy',
                email: 'banned@gmail.com',
                password: passwordHash,
                fullname: 'Thanh Niên Bị Ban',
                avatar_image_link: 'https://ui-avatars.com/api/?name=Ban&background=000&color=fff',
                role: 'MEMBER',
                is_banned: true // Test user bị ban
            },
            {
                user_id: 5,
                username: 'uetfa_ai',
                email: 'ai@uetfa.edu.vn',
                password: passwordHash,
                fullname: 'UETFA AI Assistant',
                avatar_image_link: 'https://ui-avatars.com/api/?name=AI&background=4f46e5&color=fff',
                role: 'ADMIN',
                is_banned: false // AI account
            }
        ];

        await User.bulkCreate(users);
        console.log('✅ Auth Service Seeded Successfully!');
        process.exit(0);

    } catch (error) {
        console.error('❌ Seed Auth Failed:', error);
        process.exit(1);
    }
};

seedAuth();