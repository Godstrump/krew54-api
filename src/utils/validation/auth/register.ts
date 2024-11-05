import Validator from 'validator';
import { isEmpty } from '../../isEmpty';

import { User, UserRole, Role, AuthProvider, Provider } from '../../../entity/User';
import { ErrorObject } from '../../../utils/constants';

export interface UserPayload extends User {
    confirmPassword?: string;
}

export const validateRegisterUser = (data: UserPayload): ErrorObject<User> => {
    let errors = {} as UserPayload;

    data.email = !isEmpty(data.email) ?  data.email : '';
    data.username = !isEmpty(data.username) ?  data.username : '';
    data.password = !isEmpty(data.password) ?  data.password : '';
    data.confirmPassword = !isEmpty(data.confirmPassword) ?  data.confirmPassword : '';
    data.role = !isEmpty(data.role) ?  data.role : '' as UserRole;
    data.provider = !isEmpty(data.provider) ?  data.provider : '' as AuthProvider;

    if (!Validator.isEmail(data.email)) {
        errors.email = 'Invalid Email Address!';
    }
    if (Validator.isEmpty(data.email)) {
        errors.email = 'Email Address is required!';
    }

    if (Validator.isEmpty(data.username)) {
        errors.username = 'Username is required!';
    }

    if (!Validator.isLength(data.password!, { min: 8 })) {
        errors.password = 'Password must be at least 8 characters long!';
    }
    if (Validator.isEmpty(data.password!)) {
        errors.password = 'Password is required!';
    }
    if (!Validator.equals(data.password, data.confirmPassword!)) {
        errors.confirmPassword = 'Passwords do not match!';
    }

    if (Validator.isEmpty(data.confirmPassword!)) {
        errors.confirmPassword = 'Password is required!';
    }

    const roleExists = Object.values(Role).some((v) => v === data.role.toString().toLowerCase());
    if (!roleExists) {
        errors.role = `Invalid user role '${data.role}'!`;
    }

    if (Validator.isEmpty(data.role)) {
        errors.role = `User role is required!`;
    }

    const providerExists = Object.values(Provider).some((v) => v === data.provider.toString().toLowerCase());
    if (!providerExists) {
        errors.provider = `Invalid provider '${data.provider}'!`;
    }
    if (Validator.isEmpty(data.provider)) {
        errors.provider = `Provider is required!`;
    }
    
    return {
        errors,
        isValid: isEmpty(errors)
    } as ErrorObject<User>;
};