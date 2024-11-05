import { Response } from 'express';

export const returnError = (err: any, res: Response, status: number, msg: string) => {
    console.error(err);
    return res.status(status).json({
        success: false,
        errors: { msg }
    });
};