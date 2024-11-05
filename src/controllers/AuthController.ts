import { MoreThan } from 'typeorm';
import bcrypt from 'bcryptjs';
import { get, patch, post, controller, use } from './decorators';
import { Request, Response } from 'express';
import crypto from 'crypto';
import Validator from 'validator';

import { 
    // validateChangePassword, 
    validateLoginUser, 
    // validateUpdateUser,
    validateRegisterUser,
    validateResetPassword,
    // ChangePasswordData,
    ResetData 
} from '../utils/validation/auth';
import { User } from '../entity';
import { ErrorObject } from '../utils/constants';
import { returnError } from '../utils/returnError';
// import { sendTokenResponse } from '../utils/sendTokenResponse';
import { generateOtp } from '../utils/generateOtp';
import { protect } from '../utils/auth';
import { sendEmail } from '../utils/sendEmail';
import { sendTokenResponse } from '../utils/sendTokenResponse';

@controller('/auth')
export class AuthController {
    // Login existing user
    @post('/login')
    async login(req: Request, res: Response) {
        try {
            const { errors, isValid }: ErrorObject<User> = validateLoginUser(req.body);
            const email = req.body.email.toLowerCase();
    
            if (!isValid) {
                return res.status(400).json({
                    success: false,
                    errors: { msg: 'Invalid login details', ...errors }
                });
            }
    
            const user = await User.findOne({ where: { email }, select: ['id', 'email', 'password', 'emailVerified', 'role', 'provider', 'createdAt', 'updatedAt']  });
    
            if (!user) {
                return res.status(401).json({
                    success: false,
                    errors: {
                        msg: 'Invalid Login Credentials!'
                    }
                });
            }
    
            // Check if password matches
            const isMatch = await user.matchPassword(req.body.password);
    
            if (!isMatch) {
                return res.status(401).json({
                    success: false,
                    errors: {
                        msg: 'Invalid Login Credentials'
                    }
                });
            }
            
            if (!user.emailVerified) {
                const otp = generateOtp();
                user.otp = otp;
                user.otpExpire = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
                await user.save();
                return res.status(403).json({
                    success: false,
                    errors: {
                        msg: `Email not verified. An OTP has been sent to ${user.email}.`,
                    }
                });
            }

            user.password = undefined!; // Remove password from user before sending response
            return sendTokenResponse(user, 200, 'Login successful', res);
        } catch (err) {
            return returnError(err, res, 500, 'Login failed');
        }
    }

    // Register new user
    @post('/register')
    async register(req: Request, res: Response) {
        try {
            const { isValid, errors }: ErrorObject<User> = validateRegisterUser(req.body);
            
            if (!isValid) {
                return res.status(400).json({
                    success: false,
                    errors: { msg: 'Invalid user data', ...errors }
                });
            }
            
            const user = await User.findOneBy({ email: req.body.email.toLowerCase() });

            if (user) {
                return res.status(400).json({
                    success: false,
                    errors: { msg: `A user with this email already exists` }
                });
            }

            const usernameExists = await User.countBy({ username: req.body.username });
            if (usernameExists) {
                return res.status(400).json({
                    success: false,
                    errors: { msg: `A user with this username already exists` }
                });
            }
            
            const newUser: User = await User.create(req.body);
            const otp = generateOtp();
            newUser.otp = otp;
            newUser.otpExpire = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
            
            // Create reset url
            // const protocol = process.env.NODE_ENV === 'development' ? 'http' : 'https';
            // const host = process.env.NODE_ENV === 'development' ? req.headers['x-forwarded-host'] ?? req.headers['host'] : req.headers['host'];
            // const resetToken = newUser.getResetPasswordToken();
            // const resetUrl = `${protocol}://${host}/auth/resetPassword?token=${resetToken}`;
            // const message = 'You are receiving this email because an account was recently created for you on the Seminary website. Please click the "Reset Password" button below to reset your password and enable you login.';

            await newUser.save(),
            newUser.password = undefined!;
    
            await Promise.all([
                newUser.save(),
                sendEmail({
                    to: newUser.email,
                    subject: 'Successful Account Creation',
                    text: `OTP for account verification: ${otp}`,
                    // template: process.env.WELCOME_TEMPLATE,
                    // variables: {
                    //     name: `${newUser.firstName} ${newUser.lastName}`,
                    //     message,
                    //     resetUrl,
                    //     year: new Date().getFullYear().toString()
                    // }
                })
            ]);
            return res.status(201).json({
                success: true,
                msg: `${newUser.role} created successfully`,
                data: newUser
            });
        } catch (err) {
            return returnError(err, res, 500, 'Unable to register user');
        }
    }

    // Get user by id
    @get('/:id')
    @use(protect)
    async getUserById(req: Request, res: Response) {
        try {
            const user = await User.findOne({ where: { id: req.params.id }, relations:{ profile: true } });
            if (!user) {
                return res.status(404).json({
                    success: false,
                    errors: { msg: 'User not found' },
                    data: user
                });
            }
            return res.status(200).json({
                success: true,
                msg: null,
                data: user
            });
        } catch (err) {
            return returnError(err, res, 500, 'Unable to get user');
        }
    }

    // Verify user email
    @post('/verifyEmail')
    async verifyEmail(req: Request, res: Response) {
        try {
            const { otp } = req.body;
            if(!otp) {
                return res.status(400).json({
                    success: false,
                    errors: { msg: 'OTP is required!' }
                });
            }
            let user = await User.findOneBy({ otp, otpExpire: MoreThan(new Date()) });

            if (!user) {
                return res.status(400).json({
                    success: false,
                    errors: { msg: 'Invalid or expired OTP' }
                });
            }
            
            user.emailVerified = true;
            user.otp = null;
            user.otpExpire = null;
            await user.save();
            return sendTokenResponse(user, 200, 'Email verified successfully', res);
        } catch (err) {
            return returnError(err, res, 500, 'Unable to verify email');
        }
    }

    // // Change user password
    // @patch('/changePassword')
    // @use(protect)
    // async changePassword(req: Request, res: Response) {
    //     try {
    //         const { currentPassword, newPassword }: ChangePasswordData = req.body;
    //         const { errors, isValid }: ErrorObject<ChangePasswordData> = validateChangePassword(req.body);
    
    //         if (!isValid) {
    //             return res.status(400).json({
    //                 success: false,
    //                 errors
    //             });
    //         }
    
    //         const user = await UserModel.findById(req.user.id).select('+password');

    //         if (!user) {
    //             return res.status(404).json({
    //                 success: false,
    //                 errors: {
    //                     msg: 'User does not exist!'
    //                 }
    //             });
    //         }
    
    //         if (!(await user.matchPassword(currentPassword))) {
    //             return res.status(401).json({
    //                 success: false,
    //                 errors: {
    //                     msg: 'Password incorrect!',
    //                     currentPassword: 'Password incorrect!'
    //                 }
    //             });
    //         }
    
    //         if (await user.matchPassword(newPassword)) {
    //             return res.status(401).json({
    //                 success: false,
    //                 errors: {
    //                     msg: 'New password cannot be same with old password',
    //                     newPassword: 'New password cannot be same with old password'
    //                 }
    //             });
    //         }
    
    //         user.password = newPassword;
    //         await user.save();
    //         // Send password change email
    //         sendTokenResponse({ user }, 200, 'Password changed successfully', res);
    //     } catch(err) {
    //         return returnError(err, res, 500, 'Password could not be changed');
    //     }
    // }

    // Send password reset email
    @post('/forgotPassword')
    async forgotPassword(req: Request, res: Response) {
        try {
            const { email } = req.body;
            if (!Validator.isEmail(email ?? '')) {
                return res.status(400).json({
                    success: false,
                    errors: {
                        email: 'Invalid email address!',
                        msg: 'Invalid email address!'
                    }
                });
            }

            const user = await User.findOne({ where : { email: email.toLowerCase() }});

            if (!user) {
                return res.status(404).json({
                    success: false,
                    errors: {
                        msg: 'User does not exist!',
                        email: 'User does not exist!'
                    }
                });
            }

            // Get reset token
            const resetToken = user.getResetPasswordToken();
    
            await user.save();
    
            // Create reset url
            const protocol = process.env.NODE_ENV === 'development' ? 'http' : 'https';
            const host = process.env.NODE_ENV === 'development' ? req.headers['x-forwarded-host'] ?? req.headers['host'] : req.headers['host'];
            const resetUrl = `${protocol}://${host}/auth/resetPassword?token=${resetToken}`;
            const message = 'It happens to the best of us. The good news is you can change it right now. Click the "Reset Password" button below to recover your password.';
    
            await sendEmail({
                to: email,
                subject: 'Portal Password Reset',
                // template: process.env.PASSWORD_RESET_TEMPLATE,
                text: `Reset password OTP: ${resetToken}`,
                variables: {
                    message,
                    resetUrl,
                    year: new Date().getFullYear().toString()
                }
            });
    
            return res.status(200).json({
                success: true,
                msg: `We sent an OTP to ${email}`,
                data: { }
            });
    

        } catch (err) {
            return returnError(err, res, 500, 'Unable to create and send password reset OTP');
        }
    }

    @patch('/resetPassword')
    async resetPassword(req: Request, res: Response) {
        try {
            const { errors, isValid }: ErrorObject<ResetData> = validateResetPassword(req.body);

            if (!isValid) {
                return res.status(400).json({
                    success: false,
                    errors
                });
            }

            const otp = crypto.createHash('sha256').update(req.body.otp).digest('hex');
            const user = await User.findOne({ where: {
                otp,
                otpExpire:   MoreThan(new Date())
            }});

            if (!user) {
                return res.status(404).json({
                    success: false,
                    errors: { msg: 'Invalid or expired OTP. Kindly use the forgot password page.' }
                });
            }

            user.password = await bcrypt.hash(req.body.password, 10);
            user.otp = null;
            user.otpExpire = null;
            await user.save();
            return res.status(200).json({
                success: true,
                msg: 'Your password has been successfully reset. Please proceed to login',
                data: {}
            });
        } catch (err) {
            return returnError(err, res, 500, 'Unable to reset password');
        }
    }

    @use(protect)
    @get('/')
    async getCurrentUser(req: Request, res: Response) {
        try {
            const user = await User.findOne({ where: { id: req.user.id }});
            return res.status(200).json({
                success: true,
                data: user
            });
        } catch (err) {
            return returnError(err, res, 500, 'Unable to get current user');
        }
    }

    @get('/logout')
    async logout(_req: Request, res: Response) {
        res.cookie('krew54Cookie', 'none', {
            expires: new Date(Date.now() - 10 * 1000),
            httpOnly: true
        });
        res.status(200).json({
            success: true,
            data: {}
        });
    }
}