require("dotenv").config();

const express = require("express");
const controller = require("./controller.js");
const sequelize = require("./configs/database.js");
const multer = require("multer");

const app = express();
const PORT = 3001;

app.use(express.json());

const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Not an image! Please upload an image."), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 1024 * 1024 * 5 }, // 5MB
});

app.post("/auth/register", controller.register);
app.post("/auth/login", controller.login);
app.post("/auth/google", controller.googleLogin);
app.post("/auth/refresh", controller.refreshToken);
app.post("/auth/verify", controller.verify);
app.get("/auth/users/me", controller.getMe);
app.put("/auth/users/me", upload.single("avatar"), controller.updateMe);

// Role Admin
app.post("/auth/users", controller.createUserByAdmin);
app.get("/auth/users", controller.getUsers);
app.get("/auth/users/:id", controller.getUserDetail);
app.put("/auth/users/:id", upload.single('avatar'), controller.updateUserByAdmin);

app.listen(PORT, async () => {
    try {
        await sequelize.sync({ force: false });
        console.log("Database & tables created!");

        await controller.connectMQ();
        console.log("Connect MQ successfully!");
    } catch(err) {
        console.error("Error creating:", err);
    }
})
