package data.handlers;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ResponseHandler;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JsonResponseHandler implements ResponseHandler<String> {
    private static final Logger LOGGER = LoggerFactory.getLogger(JsonResponseHandler.class);

    @Override
    public String handleResponse(HttpResponse httpResponse) {
        try {
            HttpEntity entity = httpResponse.getEntity();
            if (entity == null) {
                return "";
            } else {
                return EntityUtils.toString(entity, StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            LOGGER.error("Failed to handle JSON response", e);
            throw new RuntimeException(e);
        }
    }
}
