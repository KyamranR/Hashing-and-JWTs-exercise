const express = require("express");
const jwt = require("jsonwebtoken");
const {
  authenticateJWT,
  ensureCorrectUser,
  ensureLoggedIn,
} = require("../middleware/auth");
const User = require("../models/user");
const Message = require("../models/message");
const { SECRET_KEY } = require("../config");
const router = new express.Router();

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get("/messages/:id", ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.get(req.params.id);

    // Ensure the logged-in user is either the sender or recipient of the message
    if (
      message.from_user.username !== req.user.username &&
      message.to_user.username !== req.user.username
    ) {
      throw new Error("Unauthorized");
    }

    return res.json({ message });
  } catch (err) {
    return next(err);
  }
});

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post("/messages", ensureLoggedIn, async (req, res, next) => {
  try {
    const { to_username, body } = req.body;
    const message = await Message.create({
      from_username: req.user.username,
      to_username,
      body,
    });
    return res.json({ message });
  } catch (err) {
    return next(err);
  }
});

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post("/messages/:id/read", ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.get(req.params.id);

    // Ensure the logged-in user is the recipient
    if (message.to_user.username !== req.user.username) {
      throw new Error("Unauthorized");
    }

    const readMessage = await Message.markRead(req.params.id);
    return res.json({ message: readMessage });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
