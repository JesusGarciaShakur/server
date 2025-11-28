const jwt = require("jsonwebtoken");

const validateToken = (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: "No autorizado" });
    }

    const decreptedObj = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = decreptedObj;
    next();
  } catch (error) {
    res.status(401).json({ message: "Token no válido" });
  }
};

module.exports = validateToken;
