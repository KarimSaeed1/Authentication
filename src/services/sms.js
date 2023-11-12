// Features
const AppError = require("./appError");

// Libraries
const axios = require("axios");

class SMS {


sendSMS = async (service , message, to , next) => {

if(service == "twilio") {

const options = {
    to: to,
    from: process.env.TWILIO_NUMBER,
    body: message,
};

const client = require('twilio')(
    process.env.TWILIO_ACCOUNT,
    process.env.TWILIO_TOKEN
);

const response = await client.messages.create(options);

if (response.status === 'failed') {
    return next(
    new AppError(
        'Send sms failed ,please try again *#* لم يتم ارسال الرسالة,برجاء اعادة المحاولة',
        400
    )
    );
}
console.log(response);

} else if(service == "taqnyat") {

const apiKey = process.env.TAQNYAT_API_KEY;
const sender = process.env.TAQNYAT_SENDER;
const url = "https://api.taqnyat.sa/v1/messages";

try {
    const response = await axios.post(
    url,
    {
        sender: sender,
        recipients: [to],
        body: message,
    },
    {
        headers: {
        Authorization: `Bearer ${apiKey}`,
        },
    }
    );

    console.log('SMS Sent:', response.data);
} catch (error) {
    console.error('Error sending SMS:', error);
}
} else {
    console.log("This service is not available :",service)
    return false;
}

}

};

module.exports = SMS ;