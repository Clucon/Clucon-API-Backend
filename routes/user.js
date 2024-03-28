const userRouter = require("express").Router();
const userController = require("../controllers/user");
const { isAuthenticated } = require("../middleware/auth");

userRouter.post("/signup", userController.createUser);
// userRouter.post("/activation", userController.activateUser); To be integrated with frontend
userRouter.post("/login", userController.loginUser);
userRouter.get("/activation/:token", userController.activateUser); // to be used only in development(backend)
userRouter.get("/logout", isAuthenticated, userController.logoutUser);
userRouter.get("/:id", isAuthenticated, userController.getUserById);
userRouter.put(
  "/update-user-info",
  isAuthenticated,
  userController.updateUserInfo
);
userRouter.post(
  "/forgot-password",
  isAuthenticated,
  userController.forgotPassword
);

module.exports = userRouter;
