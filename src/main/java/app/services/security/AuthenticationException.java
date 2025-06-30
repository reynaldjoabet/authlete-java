package services.security;

import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;
import play.libs.Json;
import lombok.Getter;

public class AuthenticationException extends RuntimeException {
  @Getter private final transient Result response;

  public AuthenticationException(String msg) {
    super(msg);
     ErrorResponse error = convertToErrorResponseMessage(msg);
    response= Results.unauthorized(Json.toJson(error));
  }

  public AuthenticationException(String msg, Throwable cause) {
    super(msg, cause);
    ErrorResponse error = convertToErrorResponseMessage(msg);
    response =Results.unauthorized(Json.toJson(error));
  }

  public static AuthenticationException getTokenNotPresentException() {
    String msg = "Not Authorized! Token not present";
    return new AuthenticationException(msg);
  }

  public static AuthenticationException getInvalidTokenException(String reason) {
    String msg = String.format("Not Authorized! %s", reason);
    return new AuthenticationException(msg);
  }

  public static AuthenticationException getInvalidTokenException(String reason, Exception e) {
    String msg = String.format("Not Authorized! %s due to %s", reason, e);
    return new AuthenticationException(msg);
  }

  public static AuthenticationException getExpiredTokenException() {
    String msg = "Expired token!";
    return new AuthenticationException(msg);
  }

  public static AuthenticationException invalidTokenMessage() {
    String msg = "Invalid token, used after logout!";
    return new AuthenticationException(msg);
  }

  public static AuthenticationException invalidEmailMessage(String principalDomain) {
    return new AuthenticationException(
        String.format(
            "Not Authorized! Email does not match the principal domain %s", principalDomain));
  }

  private static ErrorResponse convertToErrorResponseMessage(String msg) {
    return new ErrorResponse(msg);
  }

  private record ErrorResponse(String responseMessage) {}
}