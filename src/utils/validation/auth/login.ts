import Validator from 'validator';
import { isEmpty } from '../../isEmpty';

import { User } from '../../../entity/User';
import { ErrorObject } from '../../../utils/constants';


export const validateLoginUser = (data: User): ErrorObject<User> => {
    let errors = {} as User;

    data.email = !isEmpty(data.email) ?  data.email : '';
    data.password = !isEmpty(data.password) ?  data.password : '';

    if (!Validator.isEmail(data.email)) {
        errors.email = 'Invalid Email Address!';
    }
    if (Validator.isEmpty(data.email)) {
        errors.email = 'Email Address is required!';
    }

    if (Validator.isEmpty(data.password!)) {
        errors.password = 'Password is required!';
    }
    
    return {
        errors,
        isValid: isEmpty(errors)
    } as ErrorObject<User>;
};