import 'reflect-metadata';
import { DataSource } from 'typeorm';

export const AppDataSource = new DataSource({
    type: "postgres",
    // host: "localhost",
    url: process.env.DATABASE_URL || "postgres://postgres:krew54@localhost:5432/postgres",
    // port: 5432,
    // username: "postgres",
    // password: undefined,
    // database: process.env.DATABASE || 'krew54',
    synchronize: true,
    logging: process.env.NODE_ENV === 'development',
    entities: process.env.NODE_ENV === 'production' ? ['src/entity/*.js'] : ['src/entity/*.ts'],
    migrations: process.env.NODE_ENV === 'production' ? ['src/migration/*.js'] : ['src/migration/*.ts'],
    subscribers: process.env.NODE_ENV === 'production' ? ['src/subscriber/*.js'] : ['src/subscriber/*.ts']
});