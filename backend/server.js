const dotenv = require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const userRoute = require("./routes/userRoute");
const errorHandler = require("./middleware/errorMiddleware");

const app = express();

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://auth-app-saira.vercel.app",
      "http://127.0.0.1:5173",
      "http://localhost:5173",
    ],
    credentials: true,
  })
);

//Routes
app.use("/api/v1/users", userRoute);

app.get("/", (req, res) => {
  res.send("Home Page React Auth App");
});

//Error handler/Error Middleware
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
    app.listen(PORT, () => {
      console.log(`Server (react auth app) running on port ${PORT}`);
    });
  })
  .catch((err) => console.log(err));
