import Validator from 'validator';
import { isEmpty } from '../../isEmpty';

import { ErrorObject } from '../../constants';

export interface ResetData {
    password: string;
    confirmPassword: string;
    otp: string;
}

export const validateResetPassword = (data: ResetData): ErrorObject<ResetData> => {
    let errors = {} as ResetData;

    data.password = !isEmpty(data.password) ?  data.password : '';
    data.confirmPassword = !isEmpty(data.confirmPassword) ?  data.confirmPassword : '';
    data.otp = !isEmpty(data.otp) ?  data.otp : '';

    if (!Validator.isLength(data.password, { min: 8 })) {
        errors.password = 'Password must be at least 8 characters long!';
    }
    if (Validator.isEmpty(data.password)) {
        errors.password = 'Password is required!';
    }
    if (!Validator.equals(data.password, data.confirmPassword)) {
        errors.confirmPassword = 'Passwords do not match!';
    }
    if (Validator.isEmpty(data.confirmPassword!)) {
        errors.confirmPassword = 'Password is required!';
    }
    
    if (Validator.isEmpty(data.otp!)) {
        errors.otp = 'OTP is required!';
    }
    
    return {
        errors,
        isValid: isEmpty(errors)
    } as ErrorObject<ResetData>;
};