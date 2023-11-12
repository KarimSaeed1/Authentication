// Model
const User = require("../resources/user/model")

// Features
const catchAsync = require("./catchAsync")
const AppError = require("./appError")

// Classess
const Function = require("./functions")
const SMS = require("./sms")

// Objects
const newFunction = new Function()
const newSMS = new SMS()

// Libraries
const crypto = require("crypto");

// Token
const {
    signToken,
    signActivationToken,
    addToken,
    decodeToken,
    checkTokenExist
} = require("./token")

class Authentication {

// register with email
emailRegister = catchAsync(async (req, res, next) => {

const {firstName , lastName, phone, email, password, passwordConfirm, type} =req.body;
const userFound = await User.findOne({ email: email });

if (userFound)
    return next(
    new AppError(
        "This email is already used by another user*#*هذا الايميل مستخدم بالفعل",
        400
    )
); 

const newUser = new User({
    firstName: firstName,
    lastName: lastName,
    email: email,
    password: password,
    passwordConfirm: passwordConfirm,
    phone: phone,
    type: type,
    firstEmail : email,
});


let error = newUser.validateSync();
let api = process.env.API;
if (error == undefined) {
    const token = await signActivationToken(newUser);

    const url = `${req.protocol}://${api}/#/activateEmail/${token}`;

    const post_data = {
    "url":url,
    "email":newUser.email,
    "application_name":"Ayat",
    "type":"Verify your email address"
    }

    await newFunction.sendEmail(post_data)
    
    return res.status(200).json({
    message: "Please activate your email*#*من فضلك قم بتفعيل الايميل",
    });
} else {
    res.status(400).json({
    message: error.errors,
    });
}
});

// activate email
activateEmail = catchAsync(async (req, res, next) => {
const token = req.params.token;
const tokenExist = await checkTokenExist(token)


if (!token || tokenExist) {
    return next(
    new AppError(
        "This link is no longer available*#*اصبح هذا الرابط غير متاح",
        403
    )
    );
}

const decode = await decodeToken(token)

const newUser = await User.create(decode.payload);
await addToken(token)

const authToken = await signToken({ id: newUser._id, type: newUser.type });

res.status(200).json({
    token: authToken,
    message: "Activate email done successfully*#*تفعيل الايميل تم بنجاح",
});
});

// login with email
emailLogin = catchAsync(async (req, res, next) => {

const { email, password } = req.body;

if (!email || !password) {
    return next(
    new AppError(
        "Please enter email and password*#*من فضلك ادخل الايميل و كلمة المرور",
        400
    )
    );
}

const user = await User.findOne({ email: email }).select("+password");

if (!user || !(await user.correctPassword(password, user.password))) {
    return next(
    new AppError(
        "Email or password are incorrect*#*البريد الالكترونى او كلمة المرور غير صحيح",
        400
    )
    );
}

if (!user.status) {
    return next(
    new AppError(
        "Sorry this account has been suspended*#*عذراً هذا الحساب معطل",
        401
    )
    );
}

const token = await signToken({ id: user._id, type: user.type });

res.status(200).json({
    token: token,
    user: {
    _id: user._id,
    type: user.type,
    name: user.name,
    email: user.email,
    phone: user.phone,
    status: user.status,
    },
    message: "You are successfully logged in*#*تم تسجيل دخولك بنجاح",
});

});

// forget password with email
emailForgetPassword = catchAsync(async (req, res, next) => {

if(!req.body.email) {
    return next(
        new AppError(
            "Email is required *#* الايميل مطلوب",
            400
        )
    );
}
const user = await User.findOne({ email: req.body.email });

if (!user) {
    return next(
    new AppError(
        "Please add valid email address*#*من فضلك ادخل بريد الكترونى صحيح",
        400
    )
    );
}

// generate random reset token
const resetToken = user.createPasswordResetToken();

await user.save({ validateBeforeSave: false });
const api = process.env.API;

try {
    const resetUrl = `${req.protocol}://${api}/#/setNewPassword/${resetToken}`;
    const post_data = {
    "url":resetUrl,
    "email":user.email,
    "application_name":"Ayat",
    "type":"Reset Email Password"
    }

    await newFunction.sendEmail(post_data)

    res.status(200).json({
    message:
        "reset password link send to your email*#*تم ارسال اللينك الى الايميل الخاص بك",
    });
} catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpire = undefined;
    await user.save({ validateBeforeSave: false });
    
    return next(
    new AppError(
        "Email doesn't send please try again*#*لم يتم ارسال الايميل من فضلك حاول مره اخرى ",
        403
    )
    );
}
});

// reset password with email
emailResetPassword = catchAsync(async (req, res, next) => {

const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

console.log(hashedToken);
const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetTokenExpire: { $gt: Date.now() },
});

const tokenExist = await checkTokenExist(req.params.token)

if (!user || tokenExist) {
    return next(
    new AppError(
        "This link is invalid,please try again to reset password*#*هذا الرابط اصبح غير متاح , قم باعاده تغيير كلمه المرور مره اخرى",
        403
    )
    );
}

const { password, passwordConfirm } = req.body;

if (!(password && passwordConfirm))
    return next(
    new AppError(
        "Please enter the new password and it's confirm*#*من فضلك ادخل كلمة السر الجديده وتأكيدها",
        400
    )
    );

user.password = password;
user.passwordConfirm = passwordConfirm;
user.passwordChangedAt = Date.now();
user.passwordResetToken = undefined;
user.passwordResetTokenExpire = undefined;

await user.save({validateBeforeSave : false});

const token = await signToken({ id: user._id, type: user.type });

await addToken(req.params.token)

res.status(200).json({
    token: token,
    message: "Chagne password done successfully*#*تم تغيير كلمة المرور بنجاح",
});
});

// reset email stage one 
resetEmailStage1 = catchAsync(async (req, res, next) => {
const email = req.body.email;

if (!email)
    return next(
    new AppError("Please enter the email ,  من فضلك ادخل الايميل", 400)
    );

const user = await User.findOne({ email: email });

if (!user)
    return next(
    new AppError(
        "Please enter your valid email ,  من فضلك ادخل الايميل الصحيح",
        400
    )
    );

const resetToken = await user.createEmailResetToken();
await user.save({ validateBeforeSave: false });
const api = process.env.API;

try {
    const resetUrl = `${req.protocol}://${api}/#/updateEmail/${resetToken}`;

    const post_data = {
    "url":resetUrl,
    "email":user.email,
    "application_name":"Ayat",
    "type":"Reset Email Address"
    }

    await newFunction.sendEmail(post_data)

    res.status(200).json({
    message: "reset email link send to your email*#*تم ارسال اللينك الى الايميل الخاص بك",
    });
} catch (err) {
    user.emailResetToken = undefined;
    user.emailResetTokenExpire = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
    new AppError(
        "Email doesn't send please try again*#*لم يتم ارسال الايميل من فضلك حاول مره اخرى ",
        403
    )
    );
}
});

// reset email stage two
resetEmailStage2 = catchAsync(async (req, res, next) => {

const hashedToken = crypto
    .createHash("sha512")
    .update(req.params.token)
    .digest("hex");

const user = await User.findOne({
    emailResetToken: hashedToken,
    emailResetTokenExpire: { $gt: Date.now() },
});

const tokenExist = await checkTokenExist(req.params.token)

if (!user || tokenExist) {
    return next(
    new AppError(
        "This link is invalid,please try again to reset password*#*هذا الرابط اصبح غير متاح , قم باعاده تغيير كلمه المرور مره اخرى",
        403
    )
    );
}

const newEmail = req.body.newEmail;

if (!newEmail || newEmail == user.email)
    return next(
    new AppError(
        "Please enter the new email*#*من فضلك ادخل الحساب الجديد",
        400
    )
    );

user.emailResetToken = undefined;
user.emailResetTokenExpire = undefined;
const resetToken = await user.createEmailResetToken2();
user.newEmail = newEmail;
await user.save({ validateBeforeSave: false });
const api = process.env.API;

try {
    const resetUrl = `${req.protocol}://${api}/#/emailUpdated/${resetToken}`;
    user.email = newEmail;
    await addToken(req.params.token)

    const post_data = {
    "url":resetUrl,
    "email":user.email,
    "application_name":"Ayat",
    "type":"Reset Email Address"
    }

    await newFunction.sendEmail(post_data)

    res.status(200).json({
    message: "We have sent an activtion link to your email*#*تم ارسال رابط التفعيل الى الحساب الجديد الخاص بك",
    });

} catch (err) {
    user.emailResetToken = undefined;
    user.emailResetTokenExpire = undefined;
    await user.save({ validateBeforeSave: false });
    
    return next(
    new AppError(
        "Email doesn't send please try again*#*لم يتم ارسال الايميل من فضلك حاول مره اخرى ",
        403
    )
    );
}
});

// update email final stage
updateEmail = catchAsync(async (req, res, next) => {

const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

const user = await User.findOne({
    emailResetToken: hashedToken,
    emailResetTokenExpire: { $gt: Date.now() },
});

const tokenExist = await checkTokenExist(req.params.token)

if (!user || tokenExist) {
    return next(
    new AppError(
        "This link is invalid,please try again to update email*#*هذا الرابط غير متاح , قم باعاده تغيير الايميل مره اخرى",
        403
    )
    );
}

const email = user.newEmail;

if (!email)
    return next(
    new AppError("Please enter the new email*#*من فضلك ادخل الايميل الجديد" , 400)
    );

await User.findByIdAndUpdate(
    user._id,
    { email: email },
    {
    new: false,
    runValidators: true,
    }
);

user.newEmail = undefined;
user.emailResetToken = undefined;
user.emailResetTokenExpire = undefined;
user.emailChangedAt = Date.now();

await user.save({ validateBeforeSave: false });

await addToken(req.params.token)

res.status(200).json({
    message: "Chagne email done successfully*#*تم تغيير الايميل بنجاح",
});

});

// update password
updatePassword = catchAsync(async (req, res, next) => {

const user = await User.findById(req.user.id).select("+password");

if (!user) {
    return next(
    new AppError("Please login first*#*من فضلك قم بتسجيل الدخول اولا", 401)
    );
}

if (
    !(req.body.currentPassword || req.body.password || req.body.passwordConfirm)
) {
    return next(
    new AppError(
        "Please enter the current password and the new*#*من فضلك قم بادخال الباسورد الحالى والجديد",
        400
    )
    );
}

if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return next(
    new AppError("Password is incorrect*#*كلمه السر هذه خاطئه", 400)
    );
}

user.password = req.body.password;
user.passwordConfirm = req.body.passwordConfirm;

await user.save({validateBeforeSave : false});

const token = await signToken({ id: user._id, type: user.type });

res.status(200).json({
    token,
    message: "Password changed successfully*#*تم تغيير كلمة المرور بنجاح",
});
});

// register with phone
phoneRegister = catchAsync(async (req, res, next) => {

const {
    name,
    phone,
    phoneCode,
    password,
    passwordConfirm,
} = req.body;

const userFound = await User.findOne({ phone: phone });

if (userFound && userFound.verified == true)
    return next(
    new AppError(
        'This phone is already used by another user*#*هذا الجوال مستخدم بالفعل',
        400
    )
    );

if (userFound) {
    const verificationCode = newFunction.code();
    userFound.verificationCode = verificationCode;
    userFound.name = name;
    userFound.password = password;
    userFound.passwordConfirm = passwordConfirm;

    await newSMS.sendSMS("","","",next);

    await userFound.save();

    return res.status(200).json({
    message:
        'Verification code sent to your phone number*#*تم ارسال كود التفعيل على الرقم الخاص بك',
    });
} else {
    const newUser = new User({
    name: name,
    password: password,
    passwordConfirm: passwordConfirm,
    phone: phone,
    phoneCode: phoneCode,
    });

    let error = newUser.validateSync();
    if (error == undefined) {
    const verificationCode = newFunction.code();
    newUser.verificationCode = verificationCode;

    await newSMS.sendSMS("","","",next);

    await newUser.save({validateBeforeSave : false});

    return res.status(200).json({
        message:
        'Verification code sent to your phone number *#*تم ارسال كود التفعيل على الرقم الخاص بك',
    });
    } else {
    res.status(400).json({
        message: error.errors,
    });
    }
}
});

// activate phone
activatePhone = catchAsync(async (req, res, next) => {

const user = await User.findOne({ phone: req.body.phone });

if (!user) {
    return next(
    new AppError('This phone number is incorrect *#* هذا الرقم غير صحيح', 400)
    );
} else if (user.verificationCode != req.body.verificationCode) {
    return next(
    new AppError('This code incorrect *#* هذا الكود  غير صحيح', 400)
    );
}

const authToken = await signToken({ id: user._id , type : user.type});

user.verified = true;
user.verificationCode = undefined;
await user.save({ validateBeforeSave: false });

res.status(200).json({
    token: authToken,
    message: 'Activate phone done successfully*#*تفعيل رقم الجوال تم بنجاح',
});

});

// login with phone
phoneLogin = catchAsync(async (req, res, next) => {

const { phone, password } = req.body;

if (!phone || !password) {
    return next(
    new AppError(
        'Please enter phone and password*#*من فضلك ادخل رقم الجوال و كلمة المرور',
        400
    )
    );
}

const user = await User.findOne({ phone: phone }).select('+password');

if (!user || !(await user.correctPassword(password, user.password))) {
    return next(
    new AppError(
        'Phone or password are incorrect*#*رقم الجوال او كلمة المرور غير صحيح',
        400
    )
    );
}

if (user.verified != true) {
    return next(
    new AppError(
        "You can't enter this page please login first*#*لا يمكنك دخول هذه الصفحة من فضلك قم بتسجيل الدخول اولا",
        401
    )
    );
} else {
    const token = await signToken({ id: user._id , type : user.type});

    res.status(200).json({
    token: token,
    user: {
        id : user._id,
        name: user.name,
        phone: user.phone,
    },
    message: 'You are successfully logged in*#*تم تسجيل دخولك بنجاح',
    });
}

});

// forget password with phone
phoneForgetPassword = catchAsync(async (req, res, next) => {

const user = await User.findOne({ phone: req.body.phone });

if (!user) {
    return next(
    new AppError(
        'Please add valid phone number*#*من فضلك ادخل رقم هاتف صحيح',
        400
    )
    );
}

const verificationCode = newFunction.code();
user.verificationCode = verificationCode;

await newSMS.sendSMS("","","",next);

await user.save({ validateBeforeSave: false });

return res.status(200).json({
    message:
    'Forget password code sent to your phone number *#*تم ارسال كود استعادة كلمة السر على الرقم الخاص بك',
});

});

// reset password with phone
phoneResetPassword = catchAsync(async (req, res, next) => {

const user = await User.findOne({ phone: req.body.phone });

if (user.verificationCode != req.body.verificationCode) {
    return next(new AppError('This code incorrect*#*,هذا الكود غير صحيح', 400));
}

const { password, passwordConfirm } = req.body;

if (!(password && passwordConfirm))
    return next(
    new AppError(
        "Please enter the new password and it's confirm*#*من فضلك ادخل كلمة السر الجديده وتأكيدها",
        400
    )
    );

if (await user.correctPassword(password, user.password)) {
    return next(
    new AppError(
        'Please enter new password different from the old one *#* من فضلك ادخل كلمة سر جديدة مختلفة عن القديمة',
        400
    )
    );
}

user.password = password;
user.passwordConfirm = passwordConfirm;
user.passwordChangedAt = Date.now();
user.verificationCode = undefined;

await user.save({validateBeforeSave : false});

const token = await signToken({ id: user._id , type : user.type});


res.status(200).json({
    token: token,
    message: 'Chagne password done successfully*#*تم تغيير كلمة المرور بنجاح',
});

});

// reset phone stage one
resetPhoneStage1 = catchAsync(async (req, res, next) => {

const user = await User.findOne({ phone: req.user.phone });

if (!user) {
    return next(
    new AppError(
        'Please add valid phone number*#*من فضلك ادخل رقم هاتف صحيح',
        400
    )
    );
}

const verificationCode = newFunction.code();
user.verificationCode = verificationCode;

await newSMS.sendSMS("","","",next);

await user.save({ validateBeforeSave: false });

return res.status(200).json({
    message:
    'reset phone code sent to your phone number *#*تم ارسال كود تغيير رقم الجوال على الرقم الخاص بك',
});

});

// resest phone stage two
resetPhoneStage2 = catchAsync(async (req, res, next) => {

const user = await User.findOne({ phone: req.user.phone });

if (!user) {
    return next(
    new AppError(
        'Please add valid phone number*#*من فضلك ادخل رقم هاتف صحيح',
        400
    )
    );
}

if (user.verificationCode != req.body.verificationCode) {
    return next(new AppError('This code incorrect*#*,هذا الكود غير صحيح', 400));
}

const newPhone = req.body.newPhone;

if (!newPhone || newPhone == user.phone)
    return next(
    new AppError(
        'Please enter a new phone number*#*من فضلك ادخل رقم الجوال الجديد',
        400
    )
    );

const verificationCode = newFunction.code();
user.verificationCode = verificationCode;

await newSMS.sendSMS("","","",next);

user.newPhone = newPhone;
await user.save({ validateBeforeSave: false });

return res.status(200).json({
    message:
    'reset phone code sent to your new phone number *#*تم ارسال كود تغيير رقم الجوال على الرقم الجديد الخاص بك',
});

});

// update phone final stage
updatePhone = catchAsync(async (req, res, next) => {

const user = await User.findOne({ phone: req.user.phone });

if (!user) {
    return next(
    new AppError(
        'Please add valid phone number*#*من فضلك ادخل رقم هاتف صحيح',
        400
    )
    );
}

if (user.verificationCode != req.body.verificationCode) {
    return next(new AppError('This code incorrect*#*,هذا الكود غير صحيح', 400));
}

user.phone = user.newPhone;
user.newPhone = undefined;
user.verificationCode = undefined;

await user.save({ validateBeforeSave: false });

return res.status(200).json({
    message:
    'reset phone done successfully*# تم تغيير رقم الجوال الخاص بك بنجاح',
});

});

};

module.exports = Authentication;