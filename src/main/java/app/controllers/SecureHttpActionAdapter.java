package controllers;

//Create `app/controllers/SecureHttpActionAdapter.java` to show unauthorized and forbidden messages when user’s don’t have access to an action.
import org.pac4j.core.context.HttpConstants;
import org.pac4j.play.PlayWebContext;
import org.pac4j.play.http.PlayHttpActionAdapter;
import org.pac4j.core.http.adapter.HttpActionAdapter;
import play.mvc.Result;

import static play.mvc.Results.*;

public class SecureHttpActionAdapter extends PlayHttpActionAdapter {

    // @Override
    // public Result adapt(int code, PlayWebContext context) {
    //     if (code == HttpConstants.UNAUTHORIZED) {
    //         return unauthorized(views.html.error401.render().toString()).as((HttpConstants.HTML_CONTENT_TYPE));
    //     } else if (code == HttpConstants.FORBIDDEN) {
    //         return forbidden(views.html.error403.render().toString()).as((HttpConstants.HTML_CONTENT_TYPE));
    //     } else {
    //         return super.adapt(code, context);
    //     }
    // }
}
