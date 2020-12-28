package com.api.security.app;

import com.api.security.app.controller.SpaceController;
import com.api.security.app.controller.UserController;
import com.google.common.util.concurrent.RateLimiter;
import org.dalesbred.Database;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONObject;

import static spark.Spark.*;

import java.nio.file.Files;
import java.nio.file.Paths;


public class App {

    public static void main( String[] args ) throws Exception {
        var datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter","natter_api_user","password");
        var database = Database.forDataSource(datasource);
        var path = Paths.get(App.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(path));

        var rateLimiter = RateLimiter.create(Double.parseDouble("2"));
        before(((request, response) -> {
            if (!rateLimiter.tryAcquire()){
                response.header("Retry-After","2");
                halt(429);
            }
        }));


        var spaceController = new SpaceController(database);
        post("/spaces",spaceController::createSpace);

        var userController = new UserController(database);
        post("/users", userController::registerUser);
        before(userController::authenticate);


        afterAfter((request, response) -> {
            response.type("application/json;charset=utf-8");
            response.header("X-Content-Type-Options", "nosniff");
            response.header("X-Frame-Options", "DENY");
            response.header("X-XSS-Protection", "0");
            response.header("Cache-Control", "no-store");
            response.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox");
            response.header("Server", "");
        });

        after(((request, response) -> {
            response.type("application/json");
        }));

        internalServerError(new JSONObject().put("error","internal server error").toString());
        notFound(new JSONObject().put("error","not found").toString());

    }

}
