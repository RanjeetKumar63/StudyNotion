const User = require("../models/User");
const OTP = require("../models/OTP");
const otpGenerator = "otp-generator";
const bcrypt = require("bcrypt");
const JWT = require("jsonwebtoken");
require("dotenv").config();

// send OTP

exports.sendOTP = async (req, res) => {
  try {
    // fetch email from req ki body
    const { email } = req.body;

    // check if user already exist
    const checkUserPresent = await User.findOne({ email });

    // if user already exist then return a response
    if (checkUserPresent) {
      return res.status(401).json({
        success: false,
        message: "User already registered",
      });
    }
    //generate OTP
    var otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });
    console.log("OTP generated:", otp);

    // check unique otp or not

    let result = await OTP.findOne({ otp: otp });
    while (result) {
      otp: otpGenerator(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
      });
      const result = await OTP.findOne({ otp: otp });
    }
    const otpPayload = { email, otp };

    // create an entry in for OTP

    const otpBody = await OTP.create(otpPayload);
    console.log(otpBody);

    // return response successful
    res.status(200).json({
      success: true,
      message: "OTP sent Successfully",
      otp,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// signup

exports.signUp = async (req, res) => {
  // data fetch from request ki bdy
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      accountType,
      contactNumber,
      otp,
    } = req.body;
    // validate krlo
    if (
      !firstName ||
      !lastName ||
      !email ||
      !password ||
      !confirmPassword ||
      !otp
    ) {
      return res.status(403).json({
        success: false,
        message: "All fields are required",
      });
    }
    // 2 password match krlo
    if (password !== confirmPassword) {
      return res.status(500).json({
        success: false,
        message:
          "Password and confirmPassword value does not match, Please try again",
      });
    }
    // check user already exist or not
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User is already registered",
      });
    }

    // find most recent otp store for the user

    const recentOtp = await OTP.find({ email }).sort({ createAt: -1 }).limit(1);
    console.log(recentOtp);

    // validate OTP
    if (recentOtp.length == 0) {
      // otp nt found
      return res.status(400).json({
        success: false,
        message: "OTP found",
      });
    } else if (otp !== recentOtp) {
      return res.status(400).json({
        success: false,
        message: "Invalid Otp",
      });
    }
    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // entry create in DB

    const profileDetail = Profile.create({
      gender: null,
      dataOfBirth: null,
      about: null,
      contactNumber: null,
    });

    const user = await User.create({
      firstName,
      lastName,
      email,
      contactNumber,
      password: hashedPassword,
      accountType,
      additionalDetails: profileDetail._id,
      image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName} `,
    });
    // return res.
    return res.status(200).json({
      success: true,
      message: "User is registered Successfully",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "User can not registered,Please try again",
    });
  }
};

// login

exports.login = async (req, res) => {
  try {
    // get data from req body
    const { email, password } = req.body;

    // validation data
    if (!email || !password) {
      return res.status(403).json({
        success: false,
        message: "All fields are required, Please try again",
      });
    }
    // user check  exist or not
    const user = await User.findOne({ email }).populate("additionalDetails");
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User  is not registered,Please signup first",
      });
    }
    // token generato {JWT} after password matching
    if (await bcrypt.compare(password, user.password)) {
      const payload = {
        email: user.email,
        id: user._id,
        accountType: user.accountType,
      };
      const token = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: "2h",
      });
      user.token = token;
      user.password = undefined;

      // create cookie and send response
      const options = {
        expires: new Data(Date.now() + 3 * 24 * 60 * 60 * 1000),
        httpOnly: true,
      };
      res.cookie("token", token, options).status(200).json({
        success: true,
        token,
        user,
        message: "Logged in Successfully",
      });
    } else {
      return res.status(401).json({
        success: false,
        message: "Password is incorrect",
      });
    }
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Login Failure,please try again",
    });
  }
};

// changed Password
exports.changePassword = async (req, res) => {
  // try {
  // get data from req body
  // const { email, password } = req.body;

  // get oldpassword,newpassword,confirmPassword
  // validation
  // update password in DB
  // send mail - password update
  // return response
  // } catch (error) {}
  try {
    // data fetch
    const { password, confirmPassword, token } = req.body;

    //validation
    if (password !== confirmPassword) {
      return res.json({
        success: false,
        message: "Password is not matching",
      });
    }
    // get userdetails from db using token
    const userDetails = await user.findOne({ token: token });
    // if no entry - invalid token
    if (!userDetails) {
      return res.json({
        success: false,
        message: "Token is invalid",
      });
    }
    // token time check
    if (userDetails.resetPasswordExpires < Date.now()) {
      return res.json({
        success: false,
        message: "Token is expired, please regenerate your token ",
      });
    }
    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    // password update
    await User.findOneAndUpdate(
      { token: token },
      { password: hashedPassword },
      { new: true }
    );
    // return response
    return res.status(200).json({
      success: true,
      message: "Password reset successful",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong,while sending reset mail",
    });
  }
};
