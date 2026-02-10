package filters;

import static play.mvc.Http.Status.INTERNAL_SERVER_ERROR;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import common.PlatformServiceException;
import config.HighAvailabilityConfig;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.apache.pekko.stream.Materializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Filter;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;

@Singleton
public class HAApiFilter extends Filter {

	public static final Logger LOG = LoggerFactory.getLogger(HAApiFilter.class);
	private final String HA_ENDPOINT_REGEX = "/api/.*(/?)settings/ha/.*";
	private final Pattern HA_ENDPOINT_PATTERN = Pattern.compile(HA_ENDPOINT_REGEX);

	@Inject
	public HAApiFilter(Materializer mat) {
		super(mat);
	}

	@Override
	public CompletionStage<Result> apply(Function<Http.RequestHeader, CompletionStage<Result>> next,
			Http.RequestHeader rh) {
		try {
			if (HighAvailabilityConfig.isFollower()) {
				// Only allow read access for HA follower
				if (!rh.method().equals("GET")) {
					// Also allow any HA, login, or read only specific APIs to succeed
					if (!HA_ENDPOINT_PATTERN.matcher(rh.path()).matches()) {
						Result result = Results.status(503, "API not available for follower YBA");
						return CompletableFuture.completedFuture(result);
					}
				}
			}
			return next.apply(rh);
		} catch (Exception e) {
			LOG.error("Error retrieving HA config", e);
			// throw new RuntimeException();
			throw new PlatformServiceException(INTERNAL_SERVER_ERROR, "Error retrieving HA config");
		}
	}
}
