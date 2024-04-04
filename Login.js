const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
  username: { type: String, unique: true },
  password: String,
  innercourt: { type: Boolean, default: false }
});

module.exports = mongoose.model('User', userSchema);

function checkUser(req, res, next) {
    console.log('checkUser called'); // add this line
    const { username, password } = req.body;
    console.log(`Username: ${username}, Password: ${password}`);
    User.findOne({ username, password }, (err, user) => {
      if (err) {
        console.log(err);
        res.status(500).send('Error finding user');
      } else if (!user) {
        res.status(401).send('Incorrect username or password');
      } else {
        req.session.user = user;
        console.log(req.session.user + 'this is where the user req should show');
        next();
      }
    });
  }
  module.exports = {
    checkUser
  };
