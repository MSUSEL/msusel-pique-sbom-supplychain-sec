package data;

import data.baseClasses.BaseRequest;
import data.handlers.JsonResponseHandler;
import data.handlers.NvdCveMarshaler;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

/**
 * Inherits from Request and is used to execute GET requests against
 * the National Vulnerabilities Database
 */
public class NVDRequest extends BaseRequest {
    private static final Logger LOGGER = LoggerFactory.getLogger(NVDRequest.class);
    JsonResponseHandler handler = new JsonResponseHandler();

    public NVDRequest(String httpMethod, String baseURI, List<String> headers, List<NameValuePair> params) {
        super(httpMethod, baseURI, headers);
        this.params = params;
    }

    // if using this class as a template to extend Request functionality, overloaded constructors providing
    // options for POST/PUT etc. requests could go here. However, for the NVD, GET is likely all that will be offered.

    @Override
    public NVDResponse executeRequest() {
        // the NVD only offers HTTP GET endpoints so this class only implements executeGetRequest()
        // For different extensions of the Request superclass you might have a switch statement based on the
        // httpMethod param along with other private execute methods. e.g. executePostRequest(), executeDeleteRequest() etc.
        return executeGetRequest();
    }

    private NVDResponse executeGetRequest() {
        URI uri;
        NVDResponse nvdResponse = new NVDResponse();
        NvdCveMarshaler nvdCveMarshaler = new NvdCveMarshaler();
        HttpGet request = new HttpGet();

        try {
            uri = new URIBuilder(baseURI).addParameters(params).build();
        } catch (URISyntaxException e) {
            LOGGER.error("Could not build URI with given inputs", e);
            throw new RuntimeException(e);
        }

        request.setURI(uri);
        request.setHeaders(Utils.resolveHeaders(headers));

        try (CloseableHttpClient client = HttpClients.createDefault();
             CloseableHttpResponse response = client.execute(request)) {

            int status = response.getStatusLine().getStatusCode();
            if (status >= 200 && status < 300) {
                String json = handler.handleResponse(response);
                nvdResponse.setCveResponse(nvdCveMarshaler.unmarshalJson(json));
                nvdResponse.setStatus(status);
            } else {
                LOGGER.info("Response status: {}", status);
                throw new IOException("Failed to execute request: " + response.getStatusLine());
            }
        } catch (IOException e) {
            LOGGER.error("Request failed", e);
            throw new RuntimeException(e);
        }
        return nvdResponse;
    }
}
