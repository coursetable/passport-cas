require("axios-debug-log");
import express from "express";
import bodyParser from "body-parser";
import morgan from "morgan";
import session from "express-session";

const PORT = 9000;

import passport from "./passport";

const app = express();

app.use(morgan("tiny"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: "this is totally secret",
    resave: false,
    saveUninitialized: false,
  })
);

// Setup routes.
app.get("/ping", (req, res) => {
  res.json("pong");
});
passport(app);

// Now that routes have been created, start listening.
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
