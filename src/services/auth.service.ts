import crypto from "crypto";
import { Types } from "mongoose";
import { User, IUser } from "../models/user.model";
import { StudentProfile } from "../models/studentProfile.model";
import { TutorProfile } from "../models/tutorProfile.model";
import { hashPassword, comparePassword } from "../utils/password";
import { sha256 } from "../utils/hash";
import { ApiError } from "../utils/ApiError";
import { issueOtp, verifyOtp as verifyOtpCode } from "./otp.service";
import { sendVerificationOtpEmail, sendPasswordResetOtpEmail } from "./email.service";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  expiresInToDate,
} from "./token.service";
import { env } from "../config/env";
import { RegisterInput, LoginInput, ResetPasswordInput } from "../validators/auth.validator";

interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

// How long an unverified account is allowed to sit before it's auto-deleted
// (see the TTL index on User.unverifiedExpiresAt). Long enough that a person
// has a real chance to find the OTP email / ask for a resend, short enough
// that a typo'd or undeliverable email address doesn't permanently squat on
// a unique email/phone.
const UNVERIFIED_ACCOUNT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

const createSession = async (
  user: IUser,
  meta: { userAgent?: string; ip?: string }
): Promise<TokenPair> => {
  const sessionId = crypto.randomUUID();

  const accessToken = signAccessToken({ sub: user._id.toString(), role: user.role });
  const refreshToken = signRefreshToken({ sub: user._id.toString(), sid: sessionId });

  // Defensive: refreshSessions is `select: false` on the schema, so any caller
  // that fetched this user without explicitly re-including it would otherwise
  // have `user.refreshSessions === undefined` here, crashing on .push().
  if (!user.refreshSessions) {
    user.refreshSessions = [];
  }

  user.refreshSessions.push({
    tokenHash: sha256(`${sessionId}:${refreshToken}`),
    userAgent: meta.userAgent,
    ip: meta.ip,
    expiresAt: expiresInToDate(env.JWT_REFRESH_EXPIRES_IN),
    createdAt: new Date(),
  });

  // Cap concurrent sessions per user to avoid unbounded growth.
  if (user.refreshSessions.length > 10) {
    user.refreshSessions = user.refreshSessions.slice(-10);
  }

  await user.save();

  return { accessToken, refreshToken };
};

export const registerUser = async (input: RegisterInput): Promise<{ otpEmailSent: boolean }> => {
  const existing = await User.findOne({
    $or: [{ email: input.email }, { phone: input.phone }],
  });

  if (existing) {
    // An unverified account past its own soft-expiry can be reclaimed
    // immediately instead of making the person wait for the TTL sweep.
    const isStaleUnverified =
      !existing.isVerified &&
      existing.unverifiedExpiresAt &&
      existing.unverifiedExpiresAt.getTime() <= Date.now();

    if (isStaleUnverified) {
      await existing.deleteOne();
    } else {
      throw ApiError.conflict("An account with this email or phone already exists");
    }
  }

  const passwordHash = await hashPassword(input.password);

  const user = await User.create({
    fullName: input.fullName,
    email: input.email,
    phone: input.phone,
    passwordHash,
    role: input.role,
    isVerified: false,
    isActive: false,
    unverifiedExpiresAt: new Date(Date.now() + UNVERIFIED_ACCOUNT_TTL_MS),
  });

  const code = await issueOtp(user._id, "verify_email");

  let otpEmailSent = true;
  try {
    await sendVerificationOtpEmail(user.email, user.fullName, code);
  } catch (err) {
    // The account is already created — don't fail the whole request over an
    // email delivery problem (bad API key, provider hiccup, unverified sender
    // domain, etc). Log it server-side so it's diagnosable, surface it to the
    // caller so the UI can react (e.g. show "we couldn't email your code,
    // request a new one" instead of implying delivery succeeded), and let the
    // person retry via "resend OTP". The account still self-destructs via the
    // TTL above if verification never completes.
    otpEmailSent = false;
    // eslint-disable-next-line no-console
    console.error("Failed to send verification OTP email (register):", err);
  }

  return { otpEmailSent };
};

export const resendVerificationOtp = async (email: string): Promise<{ otpEmailSent: boolean }> => {
  const user = await User.findOne({ email });
  if (!user) return { otpEmailSent: true }; // don't leak account existence
  if (user.isVerified) return { otpEmailSent: true };

  const code = await issueOtp(user._id, "verify_email");

  // Extend the TTL window so a person actively retrying doesn't get swept
  // out from under themselves mid-flow.
  user.unverifiedExpiresAt = new Date(Date.now() + UNVERIFIED_ACCOUNT_TTL_MS);
  await user.save();

  try {
    await sendVerificationOtpEmail(user.email, user.fullName, code);
    return { otpEmailSent: true };
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error("Failed to send verification OTP email (resend):", err);
    return { otpEmailSent: false };
  }
};

export const verifyEmailOtp = async (
  email: string,
  code: string,
  meta: { userAgent?: string; ip?: string }
): Promise<{ user: IUser; tokens: TokenPair }> => {
  const user = await User.findOne({ email }).select("+refreshSessions");
  if (!user) throw ApiError.badRequest("Invalid verification request");
  if (user.isVerified) throw ApiError.badRequest("Account is already verified");

  await verifyOtpCode(user._id, "verify_email", code);

  user.isVerified = true;
  user.isActive = true;
  user.unverifiedExpiresAt = null; // account is permanent now — opt out of the TTL sweep
  await user.save();

  // Create the role-specific profile stub now that the account is active.
  if (user.role === "student") {
    await StudentProfile.findOneAndUpdate(
      { user: user._id },
      { user: user._id },
      { upsert: true }
    );
  } else if (user.role === "tutor") {
    await TutorProfile.findOneAndUpdate(
      { user: user._id },
      { user: user._id },
      { upsert: true }
    );
  }

  const tokens = await createSession(user, meta);
  return { user, tokens };
};

export const loginUser = async (
  input: LoginInput,
  meta: { userAgent?: string; ip?: string }
): Promise<{ user: IUser; tokens: TokenPair }> => {
  const user = await User.findOne({ email: input.email }).select("+passwordHash +refreshSessions");
  if (!user) throw ApiError.unauthorized("Invalid email or password");

  const isMatch = await comparePassword(input.password, user.passwordHash);
  if (!isMatch) throw ApiError.unauthorized("Invalid email or password");

  if (!user.isVerified || !user.isActive) {
    throw ApiError.forbidden("Please verify your email before logging in");
  }

  if (user.isSuspended) {
    throw ApiError.forbidden("This account has been suspended");
  }

  const tokens = await createSession(user, meta);
  return { user, tokens };
};

export const refreshSession = async (
  refreshToken: string,
  meta: { userAgent?: string; ip?: string }
): Promise<TokenPair> => {
  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch {
    throw ApiError.unauthorized("Invalid or expired refresh token");
  }

  const user = await User.findById(payload.sub).select("+refreshSessions");
  if (!user) throw ApiError.unauthorized("Invalid refresh token");

  const incomingHash = sha256(`${payload.sid}:${refreshToken}`);
  const sessionIndex = user.refreshSessions.findIndex((s) => s.tokenHash === incomingHash);

  if (sessionIndex === -1) {
    // Token reuse or forgery — invalidate all sessions as a precaution.
    user.refreshSessions = [];
    await user.save();
    throw ApiError.unauthorized("Session invalid. Please log in again.");
  }

  // Rotate: remove the used session, issue a brand new one.
  user.refreshSessions.splice(sessionIndex, 1);
  await user.save();

  return createSession(user, meta);
};

export const logoutUser = async (userId: string, refreshToken: string): Promise<void> => {
  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch {
    return; // already invalid/expired — nothing to clean up
  }

  const incomingHash = sha256(`${payload.sid}:${refreshToken}`);

  await User.updateOne(
    { _id: userId },
    { $pull: { refreshSessions: { tokenHash: incomingHash } } }
  );
};

export const forgotPassword = async (email: string): Promise<void> => {
  const user = await User.findOne({ email });
  if (!user) return; // don't leak account existence

  const code = await issueOtp(user._id, "reset_password");

  try {
    await sendPasswordResetOtpEmail(user.email, user.fullName, code);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error("Failed to send password reset OTP email:", err);
  }
};

export const resetPassword = async (input: ResetPasswordInput): Promise<void> => {
  const user = await User.findOne({ email: input.email });
  if (!user) throw ApiError.badRequest("Invalid reset request");

  await verifyOtpCode(user._id, "reset_password", input.code);

  user.passwordHash = await hashPassword(input.newPassword);
  user.refreshSessions = []; // force re-login on all devices after password reset
  await user.save();
};

export const changePassword = async (
  userId: Types.ObjectId | string,
  currentPassword: string,
  newPassword: string
): Promise<void> => {
  const user = await User.findById(userId).select("+passwordHash");
  if (!user) throw ApiError.notFound("User not found");

  const isMatch = await comparePassword(currentPassword, user.passwordHash);
  if (!isMatch) throw ApiError.badRequest("Current password is incorrect");

  user.passwordHash = await hashPassword(newPassword);
  user.refreshSessions = []; // force re-login on all devices
  await user.save();
};

/**
 * Returns the full, up-to-date profile for the logged-in user: base account
 * fields (name/email/phone/role) plus whichever role-specific profile
 * document (student or tutor) belongs to them. This backs GET /auth/me,
 * which the frontend uses to hydrate the session on page load and to
 * populate the profile screens — previously that endpoint only echoed back
 * the raw `{ id, role }` JWT payload, so none of that data ever reached the UI.
 */
export const getCurrentUserProfile = async (userId: string) => {
  const user = await User.findById(userId);
  if (!user) throw ApiError.notFound("User not found");

  const base = {
    id: user._id,
    fullName: user.fullName,
    email: user.email,
    phone: user.phone,
    role: user.role,
    isVerified: user.isVerified,
    createdAt: user.createdAt,
  };

  if (user.role === "student") {
    const profile = await StudentProfile.findOne({ user: user._id });
    return { ...base, profile };
  }

  if (user.role === "tutor") {
    const profile = await TutorProfile.findOne({ user: user._id });
    return { ...base, profile };
  }

  return { ...base, profile: null };
};

/**
 * Updates the account-level contact fields (name / phone) that live on the
 * User document rather than on the role-specific profile document. Shared by
 * both the student and tutor "update my profile" endpoints so phone-number
 * changes actually persist instead of silently being dropped (the profile
 * documents don't have a `phone` field — only User does).
 */
export const updateContactInfo = async (
  userId: string,
  updates: { fullName?: string; phone?: string }
): Promise<IUser> => {
  const user = await User.findById(userId);
  if (!user) throw ApiError.notFound("User not found");

  if (updates.phone && updates.phone !== user.phone) {
    const phoneTaken = await User.findOne({ phone: updates.phone, _id: { $ne: user._id } });
    if (phoneTaken) {
      throw ApiError.conflict("This phone number is already in use by another account");
    }
    user.phone = updates.phone;
  }

  if (updates.fullName) {
    user.fullName = updates.fullName;
  }

  await user.save();
  return user;
};
