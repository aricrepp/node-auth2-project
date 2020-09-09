const jwt = require('jsonwebtoken');

function restrict(role) {
  const roles = ['basic', 'admin'];

  return async (req, res, next) => {
    const authError = {
      message: 'Invalid credentials',
    };

    try {
      // express-session will automatically get the session ID from the cookie
      // header, and check to make sure it's valid and the session for this user exists.
      // if (!req.session || !req.session.user) {
      //   return res.status(401).json(authError);
      // }
      //assuming the token gets passed as Authorication in the header
      //used for headers
      const token = req.headers.authorization;

      // used for cookies and tokens
      // const token = req.cookies.token;

      if (!token) {
        return res.status(401).json(authError);
      }

      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).json(authError);
        }

        // if (role !== decoded.userRole) {
        //   return res.status(403).json({
        //     message: 'You shall not pass',
        //   });
        // }
        if (role && roles.indexOf(decoded.userRole) < roles.indexOf(role)) {
          return res.status(403).json({
            message: 'You shall not pass',
          });
        }

        req.token = decoded;
        next();
      });
    } catch (err) {
      next(err);
    }
  };
}

module.exports = restrict;
