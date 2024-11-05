import 'reflect-metadata';

import { AppRouter } from '../../AppRouter';
import { MetadataKeys } from './MetadataKeys';
import { Methods } from './Methods';

export function controller (routePrefix: string) {
    return function (target: Function) {
        const router = AppRouter.getInstance();

        
        for (let key of Object.getOwnPropertyNames(target.prototype)) {
            const routeHandler = target.prototype[key];
            const path = Reflect.getMetadata(MetadataKeys.path, target.prototype, key);
            const method: Methods = Reflect.getMetadata(MetadataKeys.method, target.prototype, key);
            const middlewares = Reflect.getMetadata(MetadataKeys.middleware, target.prototype, key) || [];
            // const requiredBodyProps = Reflect.getMetadata(MetadataKeys.validator, target.prototype, key) || [];


            // const validator = bodyValidators(requiredBodyProps);

            if (path) {
                router[method](`/api${routePrefix}${path}`, ...middlewares, routeHandler);
            }
        }
    }
}