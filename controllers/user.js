const User = require("../models/user");
const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const jwt = require("jsonwebtoken");
const sendToken = require("../utils/jwtToken");
const sendMail = require("../utils/sendMail");

const apiUrl =
  process.env.NODE_ENV === "development"
    ? "http://localhost:3000"
    : "https://clucon-api.onrender.com";

// create user
exports.createUser = async (req, res) => {
  try {
    const userData = req.body;
    const userEmail = await User.findOne({ email: userData.email });

    if (userEmail) {
      return res.status(400).send("User already exists");
    }

    const user = {
      ...userData,
    };

    const activationToken = createActivationToken(user);

    const activationUrl = `${apiUrl}/user/activation/${activationToken}`;

    try {
      await sendMail({
        email: user?.email,
        subject: "Activate your account",
        message: `Hello ${user.first_name}, please click on the link to activate your account: ${activationUrl}`,
      });

      res.status(201).json({
        success: true,
        message: `please check your email:- ${user.email} to activate your account!`,
      });
    } catch (error) {
      res.status(500).send(error.message);
    }
  } catch (error) {
    res.status(400).send(error.message);
  }
};

// create activation token
const createActivationToken = (user) => {
  return jwt.sign(user, process.env.ACTIVATION_SECRET, {
    expiresIn: "5m",
  });
};

// activate user
exports.activateUser = catchAsyncErrors(async (req, res) => {
  try {
    // const { activation_token } = req.body;
    const activation_token = req.params.token;

    const newUser = jwt.verify(activation_token, process.env.ACTIVATION_SECRET);

    if (!newUser) {
      return res.status(400).send("Invalid token");
    }
    const userData = newUser;

    let user = await User.findOne({ email: userData.email });

    if (user) {
      return res.status(400).send("User already exists");
    }
    user = await User.create({
      ...userData,
    });

    sendToken(user, 201, res);
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

// login user
exports.loginUser = catchAsyncErrors(async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).send("Please provide the all fields!");
    }

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return res.status(404).send("User doesn't exists!");
    }

    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      res
        .status(400)
        .send({ message: "Please provide the correct information" });
      return;
    }

    sendToken(user, 201, res);
    res.status(200).send({ message: "Login successful." });
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

// load user
exports.loadUser = catchAsyncErrors(async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(400).send({ message: "User doesn't exists" });
    }

    res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

// log out user
exports.logoutUser = catchAsyncErrors(async (req, res) => {
  try {
    res.cookie("token", null, {
      expires: new Date(Date.now()),
      httpOnly: true,
      sameSite: "none",
      secure: true,
    });
    res.status(201).json({
      success: true,
      message: "Log out successful!",
    });
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

// update user info
exports.updateUserInfo = catchAsyncErrors(async (req, res) => {
  try {
    const {
      email,
      password, //Existing password
      first_name,
      last_name,
      phoneNo,
    } = req.body;

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return res.status(400).send({ message: "User not found" });
    }

    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      return next(
        new ErrorHandler("Please provide the correct information", 400)
      );
    }

    user.email = email;
    user.password = password;
    user.first_name = first_name;
    user.last_name = last_name;
    user.phoneNo = phoneNo;

    await user.save();

    res.status(201).json({
      success: true,
      user,
    });
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

// update user password
exports.forgotPassword = catchAsyncErrors(async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    user.password = req.body.newPassword;

    await user.save();

    res.status(200).json({
      success: true,
      message: "Password updated successfully!",
    });
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

// find user information with the userId
exports.getUserById = catchAsyncErrors(async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    res.status(201).json({
      success: true,
      user,
    });
  } catch (error) {
    return res.status(500).send(error.message);
  }
});
