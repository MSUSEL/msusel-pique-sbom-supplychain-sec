package data;

import data.baseClasses.BaseRequest;
import data.handlers.SecurityAdvisoryMarshaller;
import data.handlers.JsonResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class GHSARequest extends BaseRequest {
    private static final Logger LOGGER = LoggerFactory.getLogger(GHSARequest.class);
    private final JsonResponseHandler handler = new JsonResponseHandler();
    private final String query;

    public GHSARequest(String httpMethod, String baseURI, List<String> headers, String query) {
        super(httpMethod, baseURI, headers);
        this.query = query;
    }

    @Override
    public GHSAResponse executeRequest() {
        return executeGHSARequest();
    }

    private GHSAResponse executeGHSARequest() {
        URI uri;
        GHSAResponse ghsaResponse = new GHSAResponse();
        SecurityAdvisoryMarshaller securityAdvisoryMarshaler = new SecurityAdvisoryMarshaller();

        try {
            uri = new URIBuilder(baseURI).build();
        } catch (URISyntaxException e) {
            LOGGER.error("Could not build URI with given inputs", e);
            throw new RuntimeException(e);
        }

        HttpPost request = new HttpPost();
        request.setURI(uri);
        request.setHeaders(Utils.resolveHeaders(headers));
        request.setEntity(new StringEntity(query, StandardCharsets.UTF_8));

        try (CloseableHttpClient client = HttpClients.createDefault();
             CloseableHttpResponse response = client.execute(request)) {

            int status = response.getStatusLine().getStatusCode();
            if (status >= 200 && status < 300) {
                String json = handler.handleResponse(response);
                ghsaResponse.setSecurityAdvisory(securityAdvisoryMarshaler.unmarshallJson(json));
                ghsaResponse.setStatus(status);
            } else {
                LOGGER.info("Response Status: {}", status);
                throw new IOException("Failed to execute request: " + response.getStatusLine());
            }
        } catch ( IOException e) {
            LOGGER.info("Request failed", e);
            throw new RuntimeException(e);
        }

        return ghsaResponse;
    }
}
