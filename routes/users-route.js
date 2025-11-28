const express = require("express");
const router = express.Router();
const User = require("../models/user-model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validateToken = require("../middlewares/validate-token");

// user registration
router.post("/register", async (req, res) => {
  try {
    // check if user exists
    const userExists = await User.findOne({ email: req.body.email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    // hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    req.body.password = hashedPassword;

    await User.create(req.body);

    return res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// user login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Usuario no encontrado" });
    }

    // validate password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: "Contraseña no válida" });
    }

    // validate JWT key
    if (!process.env.JWT_SECRET_KEY) {
      return res.status(500).json({
        message: "JWT_SECRET_KEY no está definida en el archivo .env",
      });
    }

    // create token
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: "7d",
    });

    return res.status(200).json({ token, message: "Inicio de sesión exitoso" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// get current user
router.get("/current-user", validateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("-password");
    return res.status(200).json({
      data: user,
      message: "Usuario obtenido exitosamente",
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// get all users
router.get("/get-all-users", validateToken, async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    return res.status(200).json({
      data: users,
      message: "Usuarios obtenidos con éxito",
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// update user
router.put("/update-user", validateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.body.userId, req.body);

    return res.status(200).json({
      message: "Usuario actualizado con éxito",
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// user logout
router.post("/logout", validateToken, async (req, res) => {
  try {
    // En JWT no se elimina el token en backend,
    // solo confirmamos que el usuario está logueado.
    return res.status(200).json({
      message: "Sesión cerrada exitosamente",
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});


module.exports = router;
