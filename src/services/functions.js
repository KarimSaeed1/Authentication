// Features
const catchAsync = require("./catchAsync")


// Libraries
const axios = require("axios");


class Function {

// send email api
sendEmail = catchAsync(async(data) => {

await axios.post(`https://ersaiss-mailer.onrender.com/send-email`,data);

// data shape
// const data = {
//     "url":url,
//     "email":newUser.email,
//     "application_name":"Medica Network",
//     "type":"Verify your email address"
// }

})

// create random code from 6 digits
code () {
  return Math.floor(100000 + Math.random() * 900000);
};


}


module.exports = Function;