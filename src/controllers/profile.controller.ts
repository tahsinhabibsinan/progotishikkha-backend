import { Request, Response } from "express";
import { HydratedDocument } from "mongoose";
import { asyncHandler } from "../utils/asyncHandler";
import { ApiResponse } from "../utils/ApiResponse";
import { ApiError } from "../utils/ApiError";
import { TutorProfile, ITutorProfile } from "../models/tutorProfile.model";
import { StudentProfile } from "../models/studentProfile.model";
import { uploadBufferToCloudinary, deleteFromCloudinary } from "../services/upload.service";
import * as authService from "../services/auth.service";

// Fields that must all be filled in before a tutor is considered
// "profile complete" and eligible to apply for tuition without waiting on
// a manual admin approval in MongoDB.
const REQUIRED_FOR_AUTO_APPROVAL: (keyof ITutorProfile)[] = [
  "qualification",
  "university",
  "department",
  "location",
  "about",
];

const isProfileComplete = (profile: HydratedDocument<ITutorProfile>): boolean =>
  REQUIRED_FOR_AUTO_APPROVAL.every((field) => {
    const value = profile[field];
    return typeof value === "string" && value.trim().length > 0;
  });

/**
 * One-way trigger: once a tutor has filled in every required field, they're
 * auto-approved and can apply immediately — no admin has to flip
 * `isApproved` in MongoDB by hand. This never revokes an approval that was
 * already granted (e.g. if a tutor later clears one field), so an admin can
 * still manually approve/suspend via the existing admin endpoints without
 * this logic fighting them.
 */
const maybeAutoApproveTutor = async (
  profile: HydratedDocument<ITutorProfile>
): Promise<HydratedDocument<ITutorProfile>> => {
  if (!profile.isApproved && isProfileComplete(profile)) {
    profile.isApproved = true;
    await profile.save();
  }
  return profile;
};

export const getTutorById = asyncHandler(async (req: Request, res: Response) => {
  // Public route (see tutor.routes.ts — no `protect` middleware) so
  // students and guests can view a tutor's profile, including contact
  // details, without logging in. passwordHash/refreshSessions can never leak
  // here even by accident: they're `select: false` at the schema level, and
  // this populate() call explicitly whitelists only these three fields.
  const profile = await TutorProfile.findById(req.params.id).populate("user", "fullName email phone");
  if (!profile) throw ApiError.notFound("Tutor not found");
  res.status(200).json(new ApiResponse(200, profile));
});

export const updateMyTutorProfile = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) throw ApiError.unauthorized();

  // fullName/phone live on the User document, not TutorProfile — split them
  // out so a phone-number change actually persists instead of being dropped
  // (Mongoose silently ignores unknown fields on a strict schema, which is
  // exactly why "phone cannot be changed" was happening before).
  const { fullName, phone, ...profileFields } = req.body;
  if (fullName || phone) {
    await authService.updateContactInfo(req.user.id, { fullName, phone });
  }

  let profile = await TutorProfile.findOneAndUpdate(
    { user: req.user.id },
    { $set: profileFields },
    { new: true, runValidators: true }
  );
  if (!profile) throw ApiError.notFound("Tutor profile not found");

  profile = await maybeAutoApproveTutor(profile);

  const me = await authService.getCurrentUserProfile(req.user.id);
  res.status(200).json(new ApiResponse(200, me, "Profile updated"));
});

export const uploadMyTutorPhoto = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) throw ApiError.unauthorized();
  if (!req.file) throw ApiError.badRequest("No photo uploaded");

  // req.user.id comes only from a verified JWT (see auth.middleware) — there
  // is no way to pass a different user's id in, so this route can only ever
  // touch the caller's own TutorProfile document.
  const profile = await TutorProfile.findOne({ user: req.user.id });
  if (!profile) throw ApiError.notFound("Tutor profile not found");

  if (profile.profilePhoto?.publicId) {
    await deleteFromCloudinary(profile.profilePhoto.publicId).catch(() => undefined);
  }

  const result = await uploadBufferToCloudinary(req.file.buffer, "profiles");
  profile.profilePhoto = result;
  await profile.save();

  res.status(200).json(new ApiResponse(200, profile, "Profile photo updated"));
});

export const updateMyStudentProfile = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) throw ApiError.unauthorized();

  const { fullName, phone, ...profileFields } = req.body;
  if (fullName || phone) {
    await authService.updateContactInfo(req.user.id, { fullName, phone });
  }

  const profile = await StudentProfile.findOneAndUpdate(
    { user: req.user.id },
    { $set: profileFields },
    { new: true, runValidators: true }
  );
  if (!profile) throw ApiError.notFound("Student profile not found");

  const me = await authService.getCurrentUserProfile(req.user.id);
  res.status(200).json(new ApiResponse(200, me, "Profile updated"));
});

// Previously missing entirely — students had no way to upload/change a
// profile photo at all (only the tutor route existed). Mirrors
// uploadMyTutorPhoto: same ownership guarantee (req.user.id from the
// verified JWT), same Cloudinary flow, same old-photo cleanup.
export const uploadMyStudentPhoto = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) throw ApiError.unauthorized();
  if (!req.file) throw ApiError.badRequest("No photo uploaded");

  const profile = await StudentProfile.findOne({ user: req.user.id });
  if (!profile) throw ApiError.notFound("Student profile not found");

  if (profile.profilePhoto?.publicId) {
    await deleteFromCloudinary(profile.profilePhoto.publicId).catch(() => undefined);
  }

  const result = await uploadBufferToCloudinary(req.file.buffer, "profiles");
  profile.profilePhoto = result;
  await profile.save();

  res.status(200).json(new ApiResponse(200, profile, "Profile photo updated"));
});
