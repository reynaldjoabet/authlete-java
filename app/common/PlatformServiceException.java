package common;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.annotations.VisibleForTesting;
import lombok.Getter;
import play.libs.Json;
import play.mvc.Http.RequestHeader;
import play.mvc.Result;
import play.mvc.Results;

public class PlatformServiceException extends RuntimeException {
    @Getter private final int httpStatus;
    @Getter private final String userVisibleMessage;
    private final JsonNode errJson;
    private final JsonNode requestJson;
    private String method;
    private String uri;

    // TODO: also accept throwable and expose stack trace in when in dev server mode
    PlatformServiceException(
        int httpStatus, String userVisibleMessage, JsonNode errJson, JsonNode requestJson) {
        super(userVisibleMessage);
        this.httpStatus = httpStatus;
        this.userVisibleMessage = userVisibleMessage;
        this.errJson = errJson;
        this.requestJson = requestJson;
    }

    public PlatformServiceException(int httpStatus, String userVisibleMessage, JsonNode errJson) {
        this(httpStatus, userVisibleMessage, errJson, null);
    }

    public PlatformServiceException(int httpStatus, String userVisibleMessage) {
        this(httpStatus, userVisibleMessage, null, null);
    }

    public PlatformServiceException(int httpStatus, JsonNode errJson) {
        this(httpStatus, "errorJson: " + errJson.toString(), errJson, null);
    }

    public PlatformServiceException(int httpStatus, JsonNode errJson, JsonNode requestJson) {
        this(httpStatus, "errorJson: " + errJson.toString(), errJson, requestJson);
    }

//    public Result buildResult(RequestHeader request) {
//        return buildResult(request.method(), request.uri());
//    }

//    public JsonNode getContentJson() {
//        return getContentJson(method, uri);
//    }
//
//
//
//    @VisibleForTesting() // for routeWithYWErrHandler
//    Result buildResult(String method, String uri) {
//        return Results.status(httpStatus, getContentJson(method, uri));
//    }
}
