// Libraries
const jwt = require("jsonwebtoken");
const fs = require("fs")
const mongoose = require("mongoose");
const { promisify } = require("util");


// Load the private key
const privateKey = fs.readFileSync('private-key.pem', 'utf8');

// Load the public key
const publicKey = fs.readFileSync('public-key.pem', 'utf8');



// prepare token model
const tokenSchema = new mongoose.Schema(
{
    token: String,
},
{
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
}
);
const Token = mongoose.model("Token", tokenSchema);



//For generate token
exports.signToken = (payload) => {
    return jwt.sign(
        {payload},
        privateKey,
        {
            algorithm: 'RS256',
            expiresIn:process.env.JWT_EXPIRES_IN,
        }
    ) 
}

//For activation token
exports.signActivationToken = (payload) => {
    return jwt.sign(
        {payload},
        privateKey,
        {
            algorithm: 'RS256',
            expiresIn:process.env.JWT_ACTIVATION_EXPIRES_IN,
        }
    ) 
}

//For decode token
exports.decodeToken = async (token) => {
try {
    const decoded = await promisify(jwt.verify)(token, publicKey, { algorithms: ['RS256'] });
    return decoded;

} catch (error) {
    console.error('Token verification error:', error.message);
}

}

//For add the token to database
exports.addToken = async (payload) => {

await Token.create({token : payload})

}
    
//For check that token exist or not
exports.checkTokenExist = async (payload) => {
const check = await Token.findOne({token : payload})

if(check) {
    return true
}
else {
    return false
}

}