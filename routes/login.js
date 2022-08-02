const express = require("express");
const joi = require("joi");
const _ = require("lodash");
const bcrypt = require("bcrypt");
const { User } = require("../models/User");
const jwt = require("jsonwebtoken");
const router = express.Router();

const loginSchema = joi.object({
  email: joi.string().required().email(),
  password: joi.string().required(),
});

const generateToken = (payload, key) => {
  const token = jwt.sign(payload, key);
  return token;
};

router.post("/", async (req, res) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) return res.status(400).send(error.message);
    let user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).send("Invaild email or password");
    const result = await bcrypt.compare(req.body.password, user.password);
    if (!result) return res.status(400).send("Invaild email or password");
    const generatedToken = jwt.sign(
      { _id: user._id, biz: user.biz },
      process.env.secretKey
    );
    res.status(200).send({ token: generatedToken });
  } catch (error) {
    res.status(400).send("error in post login");
  }
});

module.exports = router;
