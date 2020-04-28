const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets.js');

module.exports = (req, res, next) => {

  try {
    // get the token from the authorization header. Remember that typically, the
    // client will include the "type" identifier (typically "Bearer") in
    // addition to the token. So we need to strip off the type value. If we
    // didn't do that, then when it is included (like it almost always is),
    // verification will fail, because we will be trying to verify "Bearer
    // {token}" instead of "{token}". 
    //
    // See https://www.rfc-editor.org/rfc/rfc6750.html for information on
    // "bearer" tokens. 
    //
    // See https://tools.ietf.org/html/rfc2617 for information on "basic" and
    // "digest" authorization headers. 
    const token = req.headers.authorization.split(" ")[1];

    if (token) {
      jwt.verify(token, secrets.jwtSecret, (err, decodedToken) => {
        if (err) {
          res.status(401).json({ message: "You shall not pass!" });
        } else {
          req.decodedJwt = decodedToken;
          console.log(req.decodedJwt);
          next();
        }
      })
    } else {
        res.status(401).json({ message: "You shall not pass!" });
    }
  } catch (err) {
    res.status(401).json({ message: "You shall not pass!" });
  }

};