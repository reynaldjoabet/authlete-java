
package filters;

import play.mvc.*;
import play.mvc.Http.*;
import javax.inject.Inject;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import org.apache.pekko.stream.Materializer;

public class CorsFilter extends Filter {

    @Inject
    public CorsFilter(Materializer materializer) {
        super(materializer);
    }

    @Override
    public CompletionStage<Result> apply(Function<RequestHeader, CompletionStage<Result>> nextFilter, RequestHeader requestHeader) {
        // Handle preflight requests
        if ("OPTIONS".equalsIgnoreCase(requestHeader.method())) {
            return CompletableFuture.completedFuture(
                Results.status(Http.Status.ACCEPTED)
                    .withHeader("Access-Control-Allow-Methods", "GET")
                    .withHeader("Access-Control-Allow-Headers", "*")
                    .withHeader("Content-Type", "text/html")
            );
        }

        // Handle normal requests
        return nextFilter.apply(requestHeader).thenApply(result ->
            result.withHeader("Access-Control-Allow-Methods", "GET")
                  .withHeader("Access-Control-Allow-Headers", "*")
                  .withHeader("Content-Type", "text/html")
        );
    }
}
