package oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class OidcDiscoveryConfigurationClient {

	private static final Logger log = LoggerFactory.getLogger(OidcDiscoveryConfigurationClient.class);
	private final HttpClient client;
	private final ObjectMapper objectMapper;

	public OidcDiscoveryConfigurationClient() {
		this(HttpClient.newHttpClient(), new ObjectMapper());
	}

	public OidcDiscoveryConfigurationClient(HttpClient client, ObjectMapper objectMapper) {
		this.client = client;
		this.objectMapper = objectMapper;
	}

	public OidcDiscoveryConfiguration fetchDiscoveryConfiguration(String discoveryUrl)
			throws IOException, InterruptedException {
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(discoveryUrl)).GET().build();

		try {
			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() >= 200 && response.statusCode() < 300) {
				return objectMapper.readValue(response.body(), OidcDiscoveryConfiguration.class);
			} else {
				throw new RuntimeException("Failed to fetch discovery configuration: HTTP " + response.statusCode());
			}
		} catch (Exception e) {
			log.error("Failed to retrieve discovery configuration from " + discoveryUrl, e);
			throw e;
		}
	}

}