package controllers;

import com.google.common.annotations.VisibleForTesting;
import com.google.inject.Inject;
import common.PlatformServiceException;
import common.ValidatingFormFactory;
//import common.audit.AuditService;
// import io.swagger.annotations.ApiKeyAuthDefinition;
// import io.swagger.annotations.Contact;
// import io.swagger.annotations.ExternalDocs;
// import io.swagger.annotations.Info;
// import io.swagger.annotations.License;
// import io.swagger.annotations.SecurityDefinition;
// import io.swagger.annotations.SwaggerDefinition;
import play.libs.Json;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.With;

//import static handlers.AuthorizationHandler.API_TOKEN_HEADER;

/**
 * This class contains dependencies, which can be used by most of the Platform controllers. An
 * example of such a functionality is the request audit.
 */

//@With({AuditAction.class, FailedRequestAction.class})
public abstract class AbstractPlatformController extends Controller {

  protected static final String LICENSE_1_0_0_NAME = "Polyform Free Trial License 1.0.0";
  protected static final String POLYFORM_FREE_TRIAL_LICENSE_1_0_0_URL =
      "https://github.com/yugabyte/yugabyte-db/blob/master/licenses/"
          + "POLYFORM-FREE-TRIAL-LICENSE-1.0.0.txt";
  protected static final String API_KEY_AUTH = "apiKeyAuth";

  @Inject protected ValidatingFormFactory formFactory;
//
//  @Inject private AuditService auditService;
//
//  protected AuditService auditService() {
//    RequestContext.get(TokenAuthenticator.USER);
//    return auditService;
//  }

//  @VisibleForTesting
//  public void setAuditService(AuditService auditService) {
//    this.auditService = auditService;
//  }

  @VisibleForTesting
  public void setFormFactory(ValidatingFormFactory formFactory) {
    this.formFactory = formFactory;
  }

  protected <T> T parseJsonAndValidate(Http.Request request, Class<T> expectedClass) {
    return formFactory.getFormDataOrBadRequest(request.body().asJson(), expectedClass);
  }

  protected <T> T parseJson(Http.Request request, Class<T> expectedClass) {
    try {
      return Json.fromJson(request.body().asJson(), expectedClass);
    } catch (Exception e) {
      throw new PlatformServiceException(
          BAD_REQUEST,
          "Failed to parse " + expectedClass.getSimpleName() + " object: " + e.getMessage());
    }
  }
}
