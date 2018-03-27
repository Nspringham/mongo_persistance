var mongoose = require("mongoose");
var bcrypt = require("bcrypt-nodejs");

var SALT_FACTOR = 10;

// Schema with its properties.
var userSchema = mongoose.Schema({
    username: {type: String, required: true, unique: true},
    password: {type: String, required: true },
    createdAt: {type: Date, default: Date.now },
    displayName: String,
    bio: String
});
//Pre-save action to hash the password
// A do-nothing function for use with the bcrypt module
var noop = function() {};
// defines a function that runs before model is saved
userSchema.pre("save", function(done) {
    // Saves a reference to the user
    var user = this;
    // skips this logic if the password has not been modified
    if(!user.isModified("password")) {
        return done();
    }
    // generate a salt for the hash and calls the inner function once completed
    bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
        if (err) { return done(err); }
        // hashes the user password
        bcrypt.hash(user.password, salt, noop, function(err, hashedPassword) {
            if (err) {return done(err); }
            // stores the password, then continues with the saving
            user.password = hashedPassword;
            done();
        });
    });
});
// Then you can add the methods.

//Checking the users password
userSchema.methods.checkPassword = function(guess, done) {
    bcrypt.compare(guess, this.password, function(err, isMatch) {
        done(err, isMatch);
    });
};

userSchema.methods.name = function() {
    return this.displayName || this.username;
};

// Creating and exporting the user model
var User = mongoose.model("User", userSchema);
module.exports = User;