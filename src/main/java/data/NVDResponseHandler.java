package data;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class NVDResponseHandler implements ResponseHandler<JSONObject> {
    private static Map<String, String[]> cveCweMap = new HashMap<>();
    private String cveId = "";
    private boolean flag;
    //private ArrayList<String> cweIds = new ArrayList<>();

    public static Map<String, String[]> getCveCweMap() {
        return cveCweMap;
    }

    @Override
    public JSONObject handleResponse(HttpResponse httpResponse) throws IOException {
        //ArrayList<String> cweIds = new ArrayList<>();
        HttpEntity entity = httpResponse.getEntity();
        //Header encodingHeader = entity.getContentEncoding();
        String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
        JSONObject jsonResponse;    // This may be redundant with the JsonReader

        /*
         * Reads incoming json as a stream and processes on the fly
         * Adapted from https://www.tutorialspoint.com/gson/gson_streaming.htm
         */
        JsonReader reader = new JsonReader(new StringReader(json));

        ArrayList<String> cweIds = new ArrayList<>();
        handleJsonObject(reader, cweIds);


        try {
            jsonResponse = new JSONObject(json);
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
        // TODO add error handling around header conversions and IO
        // TODO logging logging logging!!!
        final int statusCode = httpResponse.getStatusLine().getStatusCode();
        //

        // check where this is getting start index
        cveCweMap.forEach((key, value) -> System.out.println(key + ":" + Arrays.toString(value)));
        //System.out.println(cveId);
        return jsonResponse;
    }

    private void handleJsonObject(JsonReader reader, ArrayList<String> cweIds) throws IOException {
        reader.beginObject();

        while (true) {
            JsonToken token = reader.peek();
            if (token.equals(JsonToken.END_OBJECT)) {
                reader.endObject();
                return;
            } else if (token.equals(JsonToken.BEGIN_OBJECT)) {
                handleJsonObject(reader, cweIds);
                 //|| token.equals(JsonToken.END_ARRAY))
            } else if (token.equals(JsonToken.BEGIN_ARRAY)) {
                handleJsonArray(reader, cweIds);
            } else if (token.equals(JsonToken.END_ARRAY)) {
                reader.endArray();
            } else if (token.equals(JsonToken.NAME)){
                String name = reader.nextName();
                switch (name) {
                    case "id":
                        cveId = reader.nextString();
                        break;
                    case "description":
                        flag = true;    // needed due to duplicate key names in different arrays
                        break;
                    case "value":
                        if (flag) {
                            cweIds.add(reader.nextString());
                            cveCweMap.put(cveId, cweIds.toArray(new String[0]));
                        }
                        break;
                    // This is kind of an ugly hack. When the next JsonObject is encountered,
                    // clear the cwe list and set flag back to false.
                    // This is necessary because of duplicate key names in different arrays
                    case "cve":
                        cweIds.clear();
                        flag = false;
                }
            } else {
                reader.skipValue();
            }
        }
    }

    private void handleJsonArray(JsonReader reader, ArrayList<String> cweIds) throws IOException {
        reader.beginArray();
        while (true) {
            JsonToken token = reader.peek();
            if (token.equals(JsonToken.BEGIN_ARRAY)) {
                handleJsonArray(reader, cweIds);
            } else if (token.equals(JsonToken.END_ARRAY)) {
                reader.endArray();
                return;
                //|| (token.equals(JsonToken.END_OBJECT))) {
            } else if (token.equals(JsonToken.BEGIN_OBJECT)) {
                handleJsonObject(reader, cweIds);
            } else if (token.equals(JsonToken.END_OBJECT)) {
                reader.endObject();

            } else if (token.equals(JsonToken.NAME)) {  // Should never get hit
                String name = reader.nextName();
                System.out.println(name);
            } else {
                reader.skipValue();
            }
        }
    }

    private ArrayList<String> getCweIdsFromDescription(JsonReader reader) throws IOException {
        ArrayList<String> cweIds = new ArrayList<>();
        reader.beginArray();
        while (reader.hasNext()) {
            JsonToken token = reader.peek();
            if (token.equals(JsonToken.BEGIN_OBJECT)) {
                reader.beginObject();
            } else if (token.equals(JsonToken.END_OBJECT)) {
                reader.endObject();
            }
            if (token.equals(JsonToken.END_ARRAY)) {
                reader.endArray();
                break;
            } else {
                if (token.equals(JsonToken.NAME)) {
                    String name = reader.nextName();
                    if (name.equals("value")) {
                        cweIds.add(reader.nextString());
                    } else {
                        reader.skipValue();
                    }
                }
            }
        }
        return cweIds;
    }

    private Map<String, ArrayList<String>> writeFullDataStore() {
        // TODO handle writing entire file to store instead of filtered values for SBOM

        return new HashMap<>();
    }
}
