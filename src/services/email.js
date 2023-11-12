// Libraries
const nodemailer = require("nodemailer");
const pug = require("pug");
const sgMail = require("@sendgrid/mail");


class Email {
  constructor(user, url) {
    this.to = user.email;
    this.name = user.names;
    this.url = url;
    this.from = "";
  }

  newTransport() {
    return nodemailer.createTransport({
      host: "sandbox.smtp.mailtrap.io",
      port: 587,
      auth: {
        user: "385ceb29467499",
        pass: "4203da7a6abe9c",
      },
      connectionTimeout: 5 * 60 * 1000, // 5 min
    });
  }

  async send(template, subject) {
    const html = pug.renderFile(`${__dirname}/../views/${template}.pug`, {
      name: this.name,
      url: this.url,
      subject: subject,
      email: this.to,
    });

    const mailOptions = {
      from: this.from,
      to: this.to,
      subject: subject,
      html: html,
    };

    if (process.env.NODE_ENV == "production") {
      sgMail.setApiKey(process.env.SENDGRID_APIKEY);
      return sgMail.send(mailOptions);
    }

    return await this.newTransport().sendMail(mailOptions);
  }
};

module.exports = Email;
