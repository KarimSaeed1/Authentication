// Models
const User = require("../resources/user/model");

// Features
const catchAsync = require("../services/catchAsync");
const AppError = require("../services/appError");

// Env
const dotenv = require("dotenv");
dotenv.config({ path: "../config/config.env" });

// Libraries
const { promisify } = require("util");
const jwt = require("jsonwebtoken");
const fs = require("fs")


// Authentication
exports.userAuth = catchAsync(async (req, res, next) => {
  
  const tokenData = req.headers["authorization"];
  // Load the public key
  const publicKey = fs.readFileSync('public-key.pem', 'utf8');

  let token;

  if (tokenData != null || undefined) {
    token = tokenData.split(" ")[1];
  }
  if (!tokenData) {
    return next(
      new AppError("Please login first*#*من فضلك قم بتسجيل الدخول اولا", 401)
    );
  }
  let t;
  if (process.env.DEV_ENV === "BACK") {
    t = tokenData;
  } else {
    t = token;
  }
  const decoded = await promisify(jwt.verify)(t, publicKey, { algorithms: ['RS256'] });

  const user = await User.findById(decoded.payload.id);

  
  if (!user) {
    return next(
      new AppError(
        "You can't enter this page please login first*#*لا يمكنك دخول هذه الصفحة من فضلك قم بتسجيل الدخول اولا",
        401
      )
    );
  }

  if (user.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError(
        "You changed password recently please login again*#*لقد قمت بتغيير كلمه السر مؤخرا من فضلك قم باعاده تسجيل الدخول مره اخرى",
        401
      )
    );
  }
  
  if (!user.status) {
    return next(
      new AppError(
        "Sorry this account has been suspended please contact with your account admin or the super admin*#*عذراً هذا الحساب معطل برجاء التواصل مع مدير الحساب الخاص بك أو مدير المنصة",
        401
      )
    );
  }

  req.user = user;

  next();
});