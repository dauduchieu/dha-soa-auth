const Sequelize = require('sequelize');
const sequelize = require('../configs/database.js');

const db = {};

db.User = require('./User');

Object.keys(db).forEach(modelName => {
  if (db[modelName].associate) {
    db[modelName].associate(db);
  }
});

db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;