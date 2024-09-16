/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

const express = require("express");
const jwt = require("jsonwebtoken");
const { authenticateJWT } = require("../middleware/auth");
const User = require("../models/user");
const Message = require("../models/message");
const { SECRET_KEY } = require("../config");
const router = new express.Router();

router.post("/login", authenticateJWT, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const isAuthenticated = await User.authenticate(username, password);

    if (isAuthenticated) {
      const token = jwt.sign({ username }, SECRET_KEY);
      await User.updateLoginTimestamp(username);
      return res.json({ token });
    } else {
      return res.status(400).json({ error: "Invalid username/password" });
    }
  } catch (error) {
    return next(error);
  }
});

router.post("/register", async (req, res, next) => {
  try {
    const { username, password, first_name, last_name, phone } = req.body;
    const newUser = await User.register({
      username,
      password,
      first_name,
      last_name,
      phone,
    });

    const token = jwt.sign({ username: newUser.username }, SECRET_KEY);
    await User.updateLoginTimestamp(newUser.username);

    return res.json({ token });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
