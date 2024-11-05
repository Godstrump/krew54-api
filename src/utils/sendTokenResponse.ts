import {  Response } from 'express';
import { User } from '../entity';

interface Options {
    expires: Date;
    httpOnly: boolean;
    secure?: boolean;
}

export const sendTokenResponse = async (data: User, statusCode: number, msg: string, res: Response) => {
    // Create token
    const token = await data.getSignedJwtToken();

    const options: Options = {
        expires: new Date(Date.now() + Number(process.env.JWT_COOKIE_EXPIRE) * 24 * 60 * 60 * 1000),
        httpOnly: true
    };

    if (process.env.NODE_ENV === 'production') {
        options.secure = true
    }

    return res.status(statusCode).cookie('seminaryCookie', token).json({
        success: true,
        data: { 
            token, 
            user: data,
            msg
        }
    });
};