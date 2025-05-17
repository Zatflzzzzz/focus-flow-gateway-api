package org.myProject.focus_flow_gateway_api.api.controllers.helpers.util;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
public class HttpResponse {
    String body;
    Map<String, List<String>> headers;
    int statusCode;

    public String getBody() {
        return body;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public int getStatusCode() {
        return statusCode;
    }
}