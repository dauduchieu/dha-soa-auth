const { DataTypes } = require('sequelize');
const sequelize = require('../configs/database.js');

const User = sequelize.define('User', {
    user_id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: {
        type: DataTypes.STRING(255),
        allowNull: true, 
        unique: true     
    },
    email: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING(255),
        allowNull: true 
    },
    fullname: {
        type: DataTypes.TEXT,
        allowNull: false 
    },
    avatar_image_link: {
        type: DataTypes.STRING(255),
        allowNull: true,
        defaultValue: null
    },
    role: {
        type: DataTypes.ENUM('MEMBER', 'ADMIN'),
        allowNull: false,
        defaultValue: 'MEMBER'
    },
    is_banned: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
    }
}, {
    timestamps: true,
    tableName: 'users'
});

module.exports = User;