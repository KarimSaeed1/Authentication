const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const validator = require("validator");
const crypto = require("crypto");

const UserSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: [
        true,
        "User must has a first name , يجب أن يملك المستخدم أسم أول",
      ],
    },

    lastName: {
      type: String,
      required: [
        true,
        "User must has a last name , يجب أن يملك المستخدم أسم عائلة",
      ],
    },

    email: {
      type: String,
      required: [
        true,
        "Please enter an email , من فضلك قم بأدخال حسابك الشخصي",
      ],
      validate: {
        validator: function (e) {
          return validator.isEmail(e);
        },
        message:
          "You must provide a vaild email , يجب ان تقوم بادخال حساب صحيح",
      },
    },

    phone: {
      type: String,
      required: [
        true,
        "Please enter a phone number , من فضلك قم بأدخال رقم هاتف",
      ],
      validate: {
        validator: function (p) {
          return /^[+]?[(]?[0-9]{3}[)]?[-\s.]?[0-9]{3}[-\s.]?[0-9]{4,6}$/im.test(
            p
          );
        },
        message: "You must provide a vaild phone,من فضلك ادخل رقم هاتف صحيح",
      },
    },

    address: {
      type: Array,
      default: [],
    },

    status: {
      type: Boolean,
      default: true,
    },

    password: {
      type: String,
      required: [true, "Please enter a password , من فضلك قم بأدخال كلمة مرور"],
      minlength: [
        8,
        "Your Password canno't be shorter than 8 characters",
        "يجب ان لا تقل كلمة المرور عن 8 أحرف أو أرقام",
      ],
    },

    passwordConfirm: {
      type: String,
      required: [
        true,
        "Please confirm your password , من فضلك قم بتأكيد كلمة مرور",
      ],
      validate: {
        validator: function (el) {
          return el === this.password;
        },
        message: "Passwords dosn't match , كلمات المرور غير متشابهة",
      },
    },

    passwordChangedAt: {
      type: Date,
    },

    passwordResetToken: {
      type: String,
    },

    passwordResetTokenExpire: {
      type: Date,
    },
    emailResetToken: {
      type: String,
    },

    emailResetTokenExpire: {
      type: Date,
    },

    newEmail: {
      type: String,
    },

    firstEmail: {
      type: String,
    },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
    timestamps: true,
  }
);

UserSchema.pre("save", async function (next) {
  const salt = await bcrypt.genSalt(10);
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, salt);
  this.passwordConfirm = undefined;
  next();
});

UserSchema.pre("save", function (next) {
  if (!this.isModified("password") || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

UserSchema.methods.correctPassword = async function (
  candidatePasssword,
  userPassword
) {
  return await bcrypt.compare(candidatePasssword, userPassword);
};

UserSchema.methods.createPasswordResetToken = function () {

  const resetToken = crypto.randomBytes(32).toString("hex");
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.passwordResetTokenExpire = Date.now() + 24 * 1000 * 60 * 60;

  return resetToken;
};

UserSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

//create reset token for the existing email
UserSchema.methods.createEmailResetToken = function () {
  const resetTokenEmail = crypto.randomBytes(32).toString("hex");
  this.emailResetToken = crypto
    .createHash("sha512")
    .update(resetTokenEmail)
    .digest("hex");
  this.emailResetTokenExpire = Date.now() + 10 * 1000 * 60;

  return resetTokenEmail;
};

//create reset token for the new email
UserSchema.methods.createEmailResetToken2 = function () {
  const resetTokenEmail = crypto.randomBytes(32).toString("hex");
  this.emailResetToken = crypto
    .createHash("sha256")
    .update(resetTokenEmail)
    .digest("hex");
  this.emailResetTokenExpire = Date.now() + 10 * 1000 * 60;

  return resetTokenEmail;
};

const User = mongoose.model("User", UserSchema);
module.exports = User;
