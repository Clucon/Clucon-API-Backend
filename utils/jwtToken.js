// create token and saving that in cookies
const sendToken = (user, statusCode, res) => {
  const token = user.getJwtToken();

  // Options for cookies
  const options = {
    expires: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    sameSite: "none",
    secure: true,
  };

  const userData = {
    username: user.username,
    email: user.email,
    first_name: user.first_name,
    last_name: user.last_name,
    phoneNo: user.phoneNo,
  }

  res.status(statusCode).cookie("token", token, options).json({
    success: true,
    userData,
    token,
  });
};

module.exports = sendToken;
