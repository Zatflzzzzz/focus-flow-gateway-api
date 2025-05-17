package org.myProject.focus_flow_gateway_api.api.exceptions;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.DefaultErrorAttributes;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.HttpMessageReader;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RestController
@RequestMapping("/error")
public class CustomErrorController {

    ErrorAttributes errorAttributes = new DefaultErrorAttributes();

    @GetMapping
    public Mono<ResponseEntity<ErrorDto>> error(ServerWebExchange exchange) {
        // Создаем ServerRequest через builder
        ServerRequest request = ServerRequest.create(exchange, (List<HttpMessageReader<?>>) exchange.getAttributes());

        Map<String, Object> attributes = errorAttributes.getErrorAttributes(
                request,
                ErrorAttributeOptions.defaults()
        );

        HttpStatus status = Optional.ofNullable(attributes.get("status"))
                .filter(Integer.class::isInstance)
                .map(Integer.class::cast)
                .map(HttpStatus::resolve)
                .orElse(HttpStatus.INTERNAL_SERVER_ERROR);

        ErrorDto errorDto = ErrorDto.builder()
                .error(attributes.getOrDefault("error", "").toString())
                .errorDescription(attributes.getOrDefault("message", "").toString())
                .build();

        return Mono.just(ResponseEntity.status(status).body(errorDto));
    }
}