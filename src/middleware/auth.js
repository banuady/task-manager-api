const jwt = require('jsonwebtoken');
const User = require('../models/user');

const auth = async (req, res, next) => {
    try {
        // Get the token from header and remove "Bearer " from the beginning
        const token = req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // second argument (the salt) should be the same as in the user model
        const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });

        if (!user) {
            throw new Error();
        }

        // We want to give the route handler the access to the found user and token
        // To do this we simply store this value into new requests property (let's call req.user and req.token)
        req.token = token;
        req.user = user;
        next();
    } catch (e) {
        res.status(401).send({ error: 'Please authenticate!' });
    }
};

module.exports = auth;
