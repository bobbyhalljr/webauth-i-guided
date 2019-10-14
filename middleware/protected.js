const bcrypt = require('bcryptjs');

module.exports = {
    protected
}

// write a middleware function that checks username and password in the headers.
function protected(req, res, next){
    const { username, password } = req.headers;

    if(user && bcrypt.compareSync(password, user.password)){
        next();
    } else {
        res.status(401).json({ message: 'Invalid Credentials' });
    }
}