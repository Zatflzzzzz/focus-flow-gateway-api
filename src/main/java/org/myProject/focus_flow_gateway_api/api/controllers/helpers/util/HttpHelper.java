package org.myProject.focus_flow_gateway_api.api.controllers.helpers.util;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.myProject.focus_flow_gateway_api.api.exceptions.CustomAppException;
import org.springframework.http.HttpStatus;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class HttpHelper {

    public static HttpResponse sendHttpRequest(String urlString, String method, String requestBody,
                                               String contentType, String authToken) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        try {
            connection.setRequestMethod(method);
            connection.setRequestProperty("Content-Type", contentType);

            if (authToken != null) {
                connection.setRequestProperty("Authorization", authToken.startsWith("Bearer ")
                        ? authToken
                        : "Bearer " + authToken);
            }

            if (requestBody != null && (method.equals("POST") || method.equals("PUT"))) {
                connection.setDoOutput(true);
                try (OutputStream os = connection.getOutputStream()) {
                    byte[] input = requestBody.getBytes(StandardCharsets.UTF_8);
                    os.write(input, 0, input.length);
                }
            }

            int responseCode = connection.getResponseCode();
            String responseBody;

            try (InputStream inputStream = responseCode >= 400
                    ? connection.getErrorStream()
                    : connection.getInputStream()) {

                if (inputStream == null) {
                    responseBody = "";
                } else {
                    responseBody = new BufferedReader(
                            new InputStreamReader(inputStream, StandardCharsets.UTF_8))
                            .lines()
                            .collect(Collectors.joining("\n"));
                }
            }

            return new HttpResponse(
                    responseBody,
                    connection.getHeaderFields(),
                    responseCode
            );

        } finally {
            connection.disconnect();
        }
    }

    private static String readErrorResponse(HttpURLConnection connection) throws IOException {
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(connection.getErrorStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            return response.toString();
        }
    }
}