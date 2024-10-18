
/**
 * A sample Express server with static resources.
 */
"use strict";

const port                  = 3000;
const path                  = require("path");
const express               = require("express");
const cookieParser          = require("cookie-parser");
const app                   = express();
const { checkUser } = require("./src/myFuncs.js");
const routes  = require("./route/moveOut.js");
const middleware = require("./middleware/middleware.js");

app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));
app.use('/labels', express.static(path.join(__dirname, 'labels')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.urlencoded({ extended: true })); // For parsing form data
app.use(express.json()); // For parsing JSON data
app.use(cookieParser());
app.use(middleware.logIncomingToConsole);
app.use(checkUser)
app.use("/", routes);
app.listen(port, logStartUpDetailsToConsole); 

/**
 * Log app details to console when starting up.
 *
 * @return {void}
 */
function logStartUpDetailsToConsole() {
    let routes = [];

    // Find what routes are supported
    app._router.stack.forEach((middleware) => {
        if (middleware.route) {
            // Routes registered directly on the app
            routes.push(middleware.route);
        } else if (middleware.name === "router") {
            // Routes added as router middleware
            middleware.handle.stack.forEach((handler) => {
                let route;

                route = handler.route;
                route && routes.push(route);
            });
        }
    });

    console.info(`Server is listening on port ${port}.`);
    console.info("Available routes are:");
    console.info(routes);
}