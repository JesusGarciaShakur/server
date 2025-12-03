const express = require("express");
const { connectMongoDB } = require("./config/db-config");
const cookieParser = require("cookie-parser");
const cors = require("cors");
require("dotenv").config();

const app = express();

app.use(
  cors({
    origin: [
      "http://localhost",
      "https://localhost",
      "http://localhost:5173",

      // Capacitor / Ionic
      "capacitor://localhost",
      "ionic://localhost",

      // Tu app web
      "https://groovix2.vercel.app",

      // Tu backend (necesario para permitir la respuesta)
      "https://server-e7g2.onrender.com"
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
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
