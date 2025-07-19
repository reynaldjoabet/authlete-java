package filters;

import play.mvc.Http;
import play.libs.ws.WSClient;
import play.libs.ws.WSRequest;
import play.libs.ws.WSResponse;
import play.libs.ws.WSAuthScheme;
import be.objectify.deadbolt.java.actions.Group;
import be.objectify.deadbolt.java.actions.Restrict;
import be.objectify.deadbolt.java.actions.SubjectPresent;
public class SecurityUtils {

  private WSClient wsClient;
    // Assumes that JwtFilter added the verified JWT as attribute to the request.
    public static VerifiedJwt getFromRequest(Http.Request httpRequest) {
        return httpRequest.attrs().get(Attrs.VERIFIED_JWT);
    }

    public static boolean hasVerifiedJwt(Http.Request request) {
        return request.attrs().containsKey(Attrs.VERIFIED_JWT);
    }


    void setWsClient(WSClient wsClient) {
        WSRequest request=wsClient
            .url("taskParams().hook.getUrl()")
            .addHeader("Content-Type", "application/json")
            .addHeader("Accept", "application/json");

      request.setAuth(
              "usernamePasswordAuth.getUsername()",
              "usernamePasswordAuth.getPassword()",
              WSAuthScheme.valueOf("usernamePasswordAuth.getType().name()"));    
       request.addHeader("tokenAuth.getTokenHeader(),", "tokenAuth.getTokenValue()");
        this.wsClient = wsClient;
    }
}