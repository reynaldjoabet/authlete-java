package filters;

import org.apache.pekko.stream.Materializer;
import com.typesafe.config.Config;
import play.Logger;
import play.libs.F.Either;
import play.mvc.Filter;
import play.mvc.Http;
import play.mvc.Result;
import play.routing.HandlerDef;
import play.routing.Router;

import javax.inject.Inject;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;

import static play.mvc.Results.forbidden;

public class JwtFilter extends Filter {
    private static Logger.ALogger logger = Logger.of(JwtFilter.class);
    private static final String ERR_AUTHORIZATION_HEADER = "ERR_AUTHORIZATION_HEADER";
    private JwtCenter jwtCenter;

    private String jwtFilterTag;
    private String headerAuthorization;
    private String bearer;
    private String jwtOptionalFilterTag;

    @Inject
    public JwtFilter(Materializer mat, JwtCenter jwtCenter, Config config) {
        super(mat);
        this.jwtCenter = jwtCenter;

        jwtFilterTag = config.getString("cooksm.art.jwt.filtertag");
        headerAuthorization = config.getString("cooksm.art.jwt.header.authorization");
        bearer = config.getString("cooksm.art.jwt.header.bearer");
        jwtOptionalFilterTag = config.getString("cooksm.art.jwt.optionalfiltertag");
    }

    @Override
    public CompletionStage<Result> apply(Function<Http.RequestHeader, CompletionStage<Result>> nextFilter, Http.RequestHeader requestHeader) {
        if (!requestHeader.attrs().containsKey(Router.Attrs.HANDLER_DEF)) {
            return nextFilter.apply(requestHeader);
        }

        HandlerDef handler = requestHeader.attrs().get(Router.Attrs.HANDLER_DEF);
        List<String> modifiers = handler.getModifiers();

        if (hasNoFilterTag(modifiers)) {
            return nextFilter.apply(requestHeader);
        }

        Optional<String> authHeader = requestHeader.getHeaders().get(headerAuthorization);
        boolean isBearerNotPresent = !authHeader.filter(ah -> ah.contains(bearer)).isPresent();
        boolean shouldOptionallyFilter = modifiers.contains(jwtOptionalFilterTag);

        if (isBearerNotPresent && shouldOptionallyFilter) {
            return nextFilter.apply(requestHeader);
        }

        if (isBearerNotPresent) {
            logger.error("f=JwtFilter, error=authHeaderNotPresent");
            return CompletableFuture.completedFuture(forbidden(ERR_AUTHORIZATION_HEADER));
        }

        String token = authHeader.map(ah -> ah.replace(bearer, "")).orElse("");
        Either<JwtCenter.Error, VerifiedJwt> res = jwtCenter.verify(token);

        if (res.left.isPresent()) {
            return CompletableFuture.completedFuture(forbidden(res.left.get().toString()));
        }

        return nextFilter.apply(requestHeader.withAttrs(requestHeader.attrs().put(Attrs.VERIFIED_JWT, res.right.get())));
    }

    private boolean hasNoFilterTag(List<String> modifiers) {
        return !modifiers.contains(jwtFilterTag) && !modifiers.contains(jwtOptionalFilterTag);
    }
}