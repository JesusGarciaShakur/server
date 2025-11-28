const express = require("express");
const { connectMongoDB } = require("./config/db-config");
const cookieParser = require("cookie-parser");
const cors = require("cors");
require("dotenv").config();

const app = express();

// CORS obligatorio
app.use(
  cors({
    origin: [
      "http://localhost:5173", // para tu desarrollo
      "https://pipeline-jade.vercel.app/login", //ruta para frontend en produccion
      "https://server-e7g2.onrender.com", // ruta para back en produccion         
    ],
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

connectMongoDB();

app.use("/api/users", require("./routes/users-route"));
app.use("/api/events", require("./routes/events-route"));
app.use("/api/payments", require("./routes/payments-route"));
app.use("/api/bookings", require("./routes/bookings-route"));
app.use("/api/reports", require("./routes/reports-route"));

const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`Node+Express Server is running on port ${port}`);
});
