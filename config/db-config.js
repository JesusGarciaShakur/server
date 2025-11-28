const mongoose = require("mongoose");

const connectMongoDB = async () => {
  try {
    console.log("MONGO_URL =", process.env.MONGO_URL);

    await mongoose.connect(process.env.MONGO_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log("Conexión a MongoDB exitosa");
  } catch (error) {
    console.log("Error en conectar con Mongo: ", error);
  }
};

module.exports = { connectMongoDB };
