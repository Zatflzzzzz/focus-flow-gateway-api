package org.myProject.focus_flow_gateway_api.api.exceptions;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.stream.Collectors;
import java.util.stream.Stream;

@Log4j2
@ControllerAdvice
public class CustomExceptionHandler {

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorDto> handleAllExceptions(Exception ex) {
    log.error("Exception occurred: ", ex);

    HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
    String message = ex.getMessage();

    if (ex instanceof CustomAppException customAppException) {
      status = customAppException.getStatus();
      message = customAppException.getMessage();
    }

    return ResponseEntity
            .status(status)
            .body(ErrorDto.builder()
                    .error(status.getReasonPhrase())
                    .errorDescription(message)
                    .build());
  }

  @ExceptionHandler(MethodArgumentTypeMismatchException.class)
  public ResponseEntity<ErrorDto> handleTypeMismatchException(MethodArgumentTypeMismatchException ex) {
    if (ex.getRequiredType() != null && ex.getRequiredType().isEnum()) {
      String validValues = Stream.of(ex.getRequiredType().getEnumConstants())
              .map(Object::toString)
              .collect(Collectors.joining(", "));

      String errorMessage = String.format(
              "Invalid value '%s' for parameter '%s'. Allowed values are: %s.",
              ex.getValue(), ex.getName(), validValues
      );

      return ResponseEntity
              .status(HttpStatus.BAD_REQUEST)
              .body(ErrorDto.builder()
                      .error(HttpStatus.BAD_REQUEST.getReasonPhrase())
                      .errorDescription(errorMessage)
                      .build());
    }

    return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(ErrorDto.builder()
                    .error(HttpStatus.BAD_REQUEST.getReasonPhrase())
                    .errorDescription("Invalid parameter: " + ex.getMessage())
                    .build());
  }
}

