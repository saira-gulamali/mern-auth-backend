//note: need to use HTML sanitizer like DOMPurify or html-sanitize to protect against hacking
const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const { generateToken, hashToken } = require("../utils");
const parser = require("ua-parser-js");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");
const Token = require("../models/tokenModel");
const Cryptr = require("cryptr");
const { OAuth2Client } = require("google-auth-library");

const cryptr = new Cryptr(process.env.CRYPTR_SECRET);
const client = new OAuth2Client(process.env.VITE_GOOGLE_CLIENT_ID);

const registerUser = asyncHandler(async (req, res) => {
  // Preliminary check of route
  //   res.send("User registered");

  const { name, email, password } = req.body;

  //Validation
  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Please fill in all the required fields.");
  }
  if (password.length < 8) {
    res.status(400);
    throw new Error("Password must be at least 8 characters.");
  }
  // check if user exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("Email already in use.");
  }

  //Get user agent
  const ua = parser(req.headers["user-agent"]);

  const userAgent = [ua.ua];

  //create new user
  const user = await User.create({ name, email, password, userAgent });

  //generate json web token
  const token = generateToken(user._id);

  //send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1day
    sameSite: "none",
    secure: true,
  });

  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified, userAgent } =
      user;

    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      userAgent,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password) {
    res.status(400);
    throw new Error("please add email and password");
  }

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found, please signup");
  }

  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  if (!passwordIsCorrect) {
    res.status(400);
    throw new Error("Invalid email or password");
  }

  //Trigger 2FA for unknown UserAgent
  //Get user agent
  const ua = parser(req.headers["user-agent"]);
  // console.log('ua', ua);
  const thisUserAgent = ua.ua;
  // console.log('thisUserAgent', thisUserAgent);
  const allowedAgent = user.userAgent.includes(thisUserAgent);

  // user agent begin
  if (!allowedAgent) {
    // generate 6 digit code
    const loginCode = Math.floor(100000 + Math.random() * 900000);
    // console.log("loginCode", loginCode);
    //encrypt login code before saving to database
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

    // console.log("encryptedLoginCode", encryptedLoginCode);
    // Delete token if it exists in DB
    let userToken = await Token.findOne({ userId: user._id });
    if (userToken) {
      await userToken.deleteOne();
    }
    //Save token to DB
    await new Token({
      userId: user._id,
      loginToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 120 * (60 * 1000),
    }).save();

    res.status(400);
    throw new Error(
      "New browser or device detected. Check your email for login code"
    );
  }

  // user agent end

  //generate json web token
  const token = generateToken(user._id);

  if (user && passwordIsCorrect) {
    //send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified, userAgent } =
      user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      userAgent,
      token,
    });
  } else {
    res.status(500);
    throw new Error("Something went wrong, please try again");
  }
});

//send login code via email
const sendLoginCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  // Find login code in DB
  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or expired token, please login again");
  }

  const loginCode = userToken.loginToken;
  const decryptedLoginCode = cryptr.decrypt(loginCode);

  // console.log("decryptedLoginCode", decryptedLoginCode);

  //Send email
  const subject = "Login Access Code - MERN AUTH:APP";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@saira.com";
  const template = "loginCode";
  const name = user.name;
  const link = decryptedLoginCode;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: `Access code sent to ${email}` });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent; please try again");
  }
});

const loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("user not found");
  }

  //Find user login token
  const userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired token, please login again");
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.loginToken);
  if (loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error("Incorrect login code, please try again");
  } else {
    //Register user agent

    const ua = parser(req.headers["user-agent"]);
    // console.log("ua", ua);
    const thisUserAgent = ua.ua;
    user.userAgent.push(thisUserAgent);
    await user.save();

    //generate json web token
    const token = generateToken(user._id);

    //send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified, userAgent } =
      user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      userAgent,
      token,
    });
  }
});

const logoutUser = asyncHandler(async (req, res) => {
  //send HTTP-only cookie
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0), // now
    sameSite: "none",
    secure: true,
  });

  return res.status(200).json({ message: "Logout successful" });
});

const getUser = asyncHandler(async (req, res) => {
  // Preliminary check of route
  //  res.send("Get user");

  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified, userAgent } =
      user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      userAgent,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { name, email, phone, bio, photo } = user;

    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();

    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
      photo: updatedUser.photo,
      role: updatedUser.role,
      isVerified: updatedUser.isVerified,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

const deleteUser = asyncHandler(async (req, res) => {
  const user = User.findById(req.params.id);

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // await user.remove();

  const deleted = await User.deleteOne({ _id: req.params.id });

  res
    .status(200)
    .json({ message: `User id ${req.params.id} deleted successfully` });
});

const getUsers = asyncHandler(async (req, res) => {
  const users = await User.find().sort("-createdAt").select("-password");
  if (!users) {
    res.status(500);
    throw new Error("Something went wrong");
  }
  res.status(200).json(users);
});

const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  // console.log("token", token);

  if (!token) {
    return res.json(false);
  }

  //verify token

  const verified = jwt.verify(token, process.env.JWT_SECRET);

  if (verified) {
    return res.json(true);
  }

  return res.json(false);
});

const upgradeUser = asyncHandler(async (req, res) => {
  const { role, id } = req.body;
  const user = await User.findById(id);

  if (!user) {
    res.status(401);
    throw new Error("User not found");
  }

  user.role = role;
  await user.save();

  res.status(200).json({ message: `User role updated to ${role}` });
});

const sendAutomatedEmail = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, template, url } = req.body;

  if (!subject || !send_to || !reply_to || !template) {
    res.status(404);
    throw new Error("Missing email parameter");
  }
  // get user

  const user = await User.findOne({ email: send_to });
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  const sent_from = process.env.EMAIL_USER;
  const name = user.name;
  const link = `${process.env.FRONTEND_URL}${url}`;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "email sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  if (user.isVerified) {
    res.status(500);
    throw new Error("User already verified");
  }
  // Delete token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // Create verification token and save it to DB
  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
  // console.log("verificationToken", verificationToken);

  // Hash token and save
  const hashedToken = hashToken(verificationToken);
  await new Token({
    userId: user._id,
    verificationToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 120 * (60 * 1000), // 60 minutes
  }).save();

  // Construct verification url
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

  //Send email
  const subject = "Verify Your Account - MERN AUTH:APP";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@saira.com";
  const template = "verifyEmail";
  const name = user.name;
  const link = verificationUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "verification email sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

//Verify user

const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;
  const hashedToken = hashToken(verificationToken);

  const userToken = await Token.findOne({
    verificationToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  //Find user
  const user = await User.findOne({ _id: userToken.userId });
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  if (user.isVerified) {
    res.status(400);
    throw new Error("User is already verified");
  }
  //now verify user
  user.isVerified = true;
  await user.save();

  res.status(200).json({ message: "Account verification successful" });
});

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("No user with this email. Please register for an account.");
  }

  // Delete token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // Create verification token and save it to DB
  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  // console.log("resetToken", resetToken);

  // Hash token and save
  const hashedToken = hashToken(resetToken);
  // console.log("date now", Date.now());
  // console.log("hashedToken", hashedToken);
  await new Token({
    userId: user._id,
    resetToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 120 * (60 * 1000), // 60 minutes
  }).save();

  // Construct forgot password url
  const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

  //Send email
  const subject = "Password Reset Request - MERN AUTH:APP";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@saira.com";
  const template = "forgotPassword";
  const name = user.name;
  const link = resetUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "Password reset email sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent; please try again");
  }
});

const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;
  // console.log(resetToken);
  // console.log(password);

  const hashedToken = hashToken(resetToken);

  const userToken = await Token.findOne({
    resetToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  //Find user
  const user = await User.findOne({ _id: userToken.userId });
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  //reset user password
  user.password = password;
  await user.save();
  await userToken.deleteOne();

  res.status(200).json({ message: "Password Reset Successful; please login" });
});

const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, password } = req.body;

  const user = await User.findById(req.user._id);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  if (!oldPassword || !password) {
    res.status(400);
    throw new Error("Please enter old and new password");
  }

  //check if old password is correct
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  // save new password
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();
    res
      .status(200)
      .json({ message: "Password change successful, please re-login" });
  } else {
    res.status(400);
    throw new Error("Old password is incorrect");
  }
});

const loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body;
  // console.log("userToken", userToken);

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.VITE_GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();

  const { name, email, picture, sub } = payload;
  const password = Date.now() + sub;

  //Get user agent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  //check if the user's email exists on DB
  const user = await User.findOne({ email });

  if (!user) {
    //register new user
    const newUser = await User.create({
      name,
      email,
      password,
      photo: picture,
      userAgent,
      isVerified: true,
    });

    if (newUser) {
      //generate json web token
      const token = generateToken(newUser._id);

      //send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1day
        sameSite: "none",
        secure: true,
      });

      const {
        _id,
        name,
        email,
        phone,
        bio,
        photo,
        role,
        isVerified,
        userAgent,
      } = newUser;

      res.status(201).json({
        _id,
        name,
        email,
        phone,
        bio,
        photo,
        role,
        isVerified,
        userAgent,
        token,
      });
    }
  }

  //the user already exists so login
  if (user) {
    //generate token
    const token = generateToken(user._id);

    //send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified, userAgent } =
      user;

    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      userAgent,
      token,
    });
  }
});

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  upgradeUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
};
