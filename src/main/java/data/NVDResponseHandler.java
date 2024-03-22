package data;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class NVDResponseHandler implements ResponseHandler<JSONObject> {

    @Override
    public JSONObject handleResponse(HttpResponse httpResponse) throws ClientProtocolException, IOException {
        HttpEntity entity = httpResponse.getEntity();
        Header encodingHeader = entity.getContentEncoding();
        String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
        JSONObject jsonResponse = null;

        try {
            jsonResponse = new JSONObject(json);
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
        // TODO add error handling around header conversions and IO
        // TODO logging logging logging!!!
        final int statusCode = httpResponse.getStatusLine().getStatusCode();
        //

        return jsonResponse;
    }
}
