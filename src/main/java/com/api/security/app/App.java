package com.api.security.app;

import com.api.security.app.controller.AuditController;
import com.api.security.app.controller.SpaceController;
import com.api.security.app.controller.UserController;
import com.google.common.util.concurrent.RateLimiter;
import org.dalesbred.Database;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONObject;

import java.nio.file.Files;
import java.nio.file.Paths;

import static spark.Spark.*;


public class App {

    public static void main( String[] args ) throws Exception {

        secure("localhost.p12","changeit",null,null);

        var datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter","natter_api_user","password");
        var database = Database.forDataSource(datasource);
        var path = Paths.get(App.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(path));

        var rateLimiter = RateLimiter.create(Double.parseDouble("2"));
        var auditController = new AuditController(database);

        before(((request, response) -> {
            if (!rateLimiter.tryAcquire()){
                response.header("Retry-After","2");
                halt(429);
            }
        }));

        var spaceController = new SpaceController(database);
        post("/spaces",spaceController::createSpace);

        var userController = new UserController(database);
        before(userController::authenticate);
        before(auditController::auditRequestStart);
        afterAfter(auditController::auditRequestEnd);
        post("/users", userController::registerUser);


        get("/logs",auditController::readAuditLog);

        afterAfter((request, response) -> {
            response.type("application/json;charset=utf-8");
            response.header("X-Content-Type-Options", "nosniff");
            response.header("X-Frame-Options", "DENY");
            response.header("X-XSS-Protection", "0");
            response.header("Cache-Control", "no-store");
            response.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox");
            response.header("Server", "");
            response.header("Strict-Transport-Security", "max-age=31536000");
        });

        after(((request, response) -> {
            response.type("application/json");
        }));

        internalServerError(new JSONObject().put("error","internal server error").toString());
        notFound(new JSONObject().put("error","not found").toString());


    }

}
