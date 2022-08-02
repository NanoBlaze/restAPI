const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  //get the token
  const token = req.header("Authorization");
  if (!token) return res.status(401).send("Access denied, no token provided");

  //decryption the token and get payload
  try {
    const payload = jwt.verify(token, process.env.secretKey);
    req.payload = payload;

    next();
  } catch (error) {
    res.status(400).send("Invalid token");
  }
};
