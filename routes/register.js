const express = require("express");
const joi = require("joi");
const bcrypt = require("bcrypt");
const { User } = require("../models/User");
const jwt = require("jsonwebtoken");
const router = express.Router();

const registerSchema = joi.object({
  name: joi.string().required().min(2),
  email: joi.string().required().min(6).max(1024).email(),
  password: joi.string().required().min(8).max(1024),
  biz: joi.boolean().required(),
});

router.post("/", async (req, res) => {
  try {
    // 1.1 joi validation
    const { error } = registerSchema.validate(req.body);
    if (error) return res.status(400).send(error.message);

    // 1.2 check if user exist
    let user = await User.findOne({ email: req.body.email });
    if (user) return res.status(400).send("user already exists");

    // add new user
    user = new User(req.body);

    // decription
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(req.body.password, salt);

    // save user details
    await user.save();
    const genToken = jwt.sign(
      { id: user._id, biz: user.biz },
      process.env.secretKey
    );
    res.status(201).send({ token: genToken });
  } catch (error) {
    res.status(400).send("error creating new user");
  }
});

module.exports = router;
