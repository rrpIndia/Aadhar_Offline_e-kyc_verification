package com.aadhaar.xmlreader;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class SimpleServer {

    public static void main(String[] args) throws IOException {
        int port = 8000; // You can change the port
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        // Serve HTML form at "/"
        server.createContext("/", new FormHandler());

        // Handle form submission at "/submit"
        server.createContext("/submit", new SubmitHandler());

        server.setExecutor(null);
        System.out.println("Server started on http://localhost:" + port);
        server.start();
    }

    // Serve the signup HTML + JS
    static class FormHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Signup</title>
                </head>
                <body>
                    <h1>Signup Form</h1>
                    <form id="signupForm" method="POST" action="/submit">
                        Share Code: <input type="text" name="shareCode" maxlength="4" required><br><br>
                        Email: <input type="email" name="email"><br><br>
                        Phone: <input type="tel" name="phone"><br><br>
                        <button type="submit">Submit</button>
                    </form>
                </body>
                </html>
                """;

            exchange.sendResponseHeaders(200, html.getBytes().length);
            OutputStream os = exchange.getResponseBody();
            os.write(html.getBytes());
            os.close();
        }
    }

    // Handle form POST request
    static class SubmitHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                InputStream is = exchange.getRequestBody();
                String formData = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                Map<String, String> params = parseFormData(formData);

                // Debug output (this is where you would connect to SignatureVerifierOneFile)
                System.out.println("Received form data:");
                params.forEach((key, value) -> System.out.println(key + " = " + value));

                String response = "Form submitted successfully! Check server logs for data.";
                exchange.sendResponseHeaders(200, response.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }

    // Helper to parse application/x-www-form-urlencoded
    private static Map<String, String> parseFormData(String formData) throws IOException {
        Map<String, String> map = new HashMap<>();
        for (String pair : formData.split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts.length == 2) {
                String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
                String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
                map.put(key, value);
            }
        }
        return map;
    }
}

