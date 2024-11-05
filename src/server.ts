import express, { Application, Request, Response } from "express";
import dotenv from "dotenv";
// import path from 'path';
import morgan from "morgan";
import cors from "cors";
import colors from "colors";
// @ts-ignore
import secure from "express-force-https";
import fileUpload from "express-fileupload";

import { AppDataSource } from "./data-source";

import "./controllers/";

import { AppRouter } from "./AppRouter";

const app: Application = express();

// const main = async () => {
try {
    // Load environment variables via config.env if in development mode
    if (process.env.NODE_ENV !== "production") {
        dotenv.config();
    }

    // Connect to database
    AppDataSource.initialize()
        .then(() => console.log("Database Connected"))
        .catch((err) => console.error(err));

    app.use(secure);
    app.use(cors());
    // app.options('*', cors());

    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(
        fileUpload({
            useTempFiles: true,
            tempFileDir: "/tmp/",
            // createParentPath: true,
            safeFileNames: true,
            preserveExtension: true,
            abortOnLimit: true,
            limits: {
                fileSize: 2 * 1024 * 1024,
            },
            limitHandler: (_: Request, res: Response) => {
                return res.status(413).json({
                    success: false,
                    errors: { msg: "File too large. Maximum size 2MB!" },
                });
                // next();
            },
        })
    );

    app.use(AppRouter.getInstance());
    app.use(morgan("dev"));

    // if (process.env.NODE_ENV === 'production') {
    //     const publicPath = path.resolve(__dirname, '..', 'client', 'build');
    //     app.use(express.static(publicPath));

    //     app.get('*', (_req: Request, res: Response) => {
    //         res.sendFile(path.resolve(publicPath, 'index.html'));
    //     });
    // }

    const PORT = process.env.PORT;
    const server = app.listen(PORT, () =>
        console.log(
            colors.blue(
                `Server running in ${process.env.NODE_ENV} mode on port ${PORT}`
            )
        )
    );

    interface Error {
        message: string;
    }

    // Handle unhandled promise rejections
    process.on("unhandledRejection", (err: Error) => {
        console.error(err);
        console.log(colors.red(`Error: ${err.message}`));
        // Close server and exit process
        server.close(() => process.exit(10));
    });
} catch (err) {
    console.error(err);
}
// };

// main();

// {
//     "compilerOptions": {
//        "lib": [
//           "es5",
//           "es6"
//        ],
//        "target": "es6",
//        "module": "commonjs",
//        "moduleResolution": "node",
//        "outDir": "./build",
//        "emitDecoratorMetadata": true,
//        "experimentalDecorators": true,
//        "sourceMap": true,
//        "esModuleInterop": true,
//        "rootDir": "./src"
//     }
//  }
