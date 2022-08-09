const mongoose = require('mongoose');
const crypto = require('crypto');

// user schema
const userScheama = new mongoose.Schema(
  {
    email: {
      type: String,
      trim: true,
      required: true,
      unique: true,
      lowercase: true
    },
    name: {
      type: String,
      trim: true,
      required: true
    },
    hashed_password: {
      type: String,
      required: true
    },
    salt: String,
    role: {
      type: String,
      default: 'subscriber'
    },
    resetPasswordLink: {
      data: String,
      default: ''
    }
  },
  {
    timestamps: true
  }
);

// Virtual
// In Mongoose, a virtual is a property that is not stored in MongoDB. Virtuals are typically used for computed properties on documents.
userScheama
  .virtual('password') // Creates new field in user document
  .set(function(password) { // Must use normal callback function
    this._password = password;
    this.salt = this.makeSalt();
    this.hashed_password = this.encryptPassword(password);
  })
  .get(function() {
    return this._password;
  });

// Methods
userScheama.methods = {
  authenticate: function(plainText) {
    return this.encryptPassword(plainText) === this.hashed_password;
  },
  // Encrypt passwword
  encryptPassword: function(password) {
    if (!password) return '';
    try {
      return crypto
        .createHmac('sha512', this.salt)
        .update(password)
        .digest('hex');
    } catch (err) {
      return '';
    }
  },
  // Generate salt
  makeSalt: function() {
    return Math.round(new Date().valueOf() * Math.random()) + '';
  }
};

module.exports = mongoose.model('User', userScheama);
