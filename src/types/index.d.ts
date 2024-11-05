import { User } from './src/entity';

// declare namespace Express {
//     export interface Request {
//         user: User;
//         files: any;
//     }
//     export interface Response {
//         user: User;
//     }
// }

export {};

declare global {
    namespace Express {
        interface Request {
            user: User;
        }
    }
}