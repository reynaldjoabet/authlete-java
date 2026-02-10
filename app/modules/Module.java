package modules;

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.http.client.indirect.FormClient;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.pac4j.play.store.PlayCacheSessionStore;

public class Module extends AbstractModule {

	@Override
	protected void configure() {
		bind(SessionStore.class).to(PlayCacheSessionStore.class);
	}

	@Provides
	protected Config provideConfig(SessionStore sessionStore) {
		// Define authentication clients
		FormClient formClient = new FormClient("/loginForm", (ctx, credentials) -> {
			// Your authentication logic here
			String username = credentials.getUsername();
			String password = credentials.getPassword();
			// Validate credentials and return user profile
		});

		JwtAuthenticator jwtAuthenticator = new JwtAuthenticator(new SecretSignatureConfiguration("your-secret-key"));

		Clients clients = new Clients("/callback", formClient);

		Config config = new Config(clients);
		config.setSessionStoreFactory(p -> sessionStore);

		return config;
	}
}
