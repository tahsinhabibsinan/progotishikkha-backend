import { Router } from "express";
import * as profileController from "../controllers/profile.controller";
import { protect, authorize } from "../middleware/auth.middleware";
import { validateBody } from "../middleware/validate";
import { upload } from "../middleware/upload.middleware";
import { updateTutorProfileSchema } from "../validators/profile.validator";

const router = Router();

router.get("/:id", profileController.getTutorById); // public — no `protect`, so guests can view tutor profiles
router.patch(
  "/me",
  protect,
  authorize("tutor"),
  validateBody(updateTutorProfileSchema),
  profileController.updateMyTutorProfile
);
router.post(
  "/me/photo",
  protect,
  authorize("tutor"),
  upload.single("photo"),
  profileController.uploadMyTutorPhoto
);

export default router;
