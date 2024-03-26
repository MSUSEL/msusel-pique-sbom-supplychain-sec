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
import java.util.HashMap;
import java.util.Map;

public class NVDResponseHandler implements ResponseHandler<JSONObject> {
    private Map<String, ArrayList<String>> cveCweMap = new HashMap<>();
    private String cveId = "";

    public Map<String, ArrayList<String>> getCveCweMap() {
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

        handleJsonObject(reader);


        try {
            jsonResponse = new JSONObject(json);
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
        // TODO add error handling around header conversions and IO
        // TODO logging logging logging!!!
        final int statusCode = httpResponse.getStatusLine().getStatusCode();
        //

        cveCweMap.forEach((key, value) -> System.out.println(key + ":" + value));
        return jsonResponse;
    }

    private void handleJsonObject(JsonReader reader) throws IOException {
        reader.beginObject();
        while (reader.hasNext()) {
            if (reader.peek().equals(JsonToken.NAME)) {
                String name = reader.nextName();
            }
            if (reader.peek().equals(JsonToken.BEGIN_ARRAY)) {
                reader.beginArray();
                while (reader.hasNext()) {
                    handleJsonObject(reader);
                }
                reader.endArray();
            } else {
                if (reader.peek().equals(JsonToken.NAME)) {
                    String name = reader.nextName();
                    switch (name) {
                        case "id":
                            cveId = reader.nextString();
                            break;
                        case "description":
                            ArrayList<String> cweIds = getCweIdsFromDescription(reader);
                            //getCweIdsFromDescription
                            cveCweMap.put(cveId, cweIds);
                            break;
                    }
                }
            }
        }
    }

//    private void handleJsonObject(JsonReader reader) throws IOException {
//        ArrayList<String> cweIds;
//
//        reader.beginObject();
//
//        while (reader.hasNext()) {
//            JsonToken token = reader.peek();
//            if (token.equals(JsonToken.END_OBJECT)) {
//                reader.endObject();
//                return;
//            } else if (token.equals(JsonToken.BEGIN_OBJECT)) {  // Check that this condition gets hit at all
//                reader.beginObject();
//            } else if (token.equals(JsonToken.BEGIN_ARRAY)) {
//                handleJsonArray(reader);
//            } else if (token.equals(JsonToken.NAME)){
//                String name = reader.nextName();
//                switch (name) {
//                    case "id":
//                        cveId = reader.nextString();
//                        break;
//                    case "description":
//                        cweIds = getCweIdsFromDescription(reader);
//                        //getCweIdsFromDescription
//                        cveCweMap.put(cveId, cweIds);
//                       break;
//                }
//            } else {
//                reader.skipValue();
//            }
//        }
//    }
//
    private ArrayList<String> getCweIdsFromDescription(JsonReader reader) throws IOException {
        ArrayList<String> cweIds = new ArrayList<>();
        reader.beginArray();
        while (reader.hasNext()) {
            JsonToken token = reader.peek();
//            if (token.equals(JsonToken.BEGIN_OBJECT)) {
//                reader.beginObject();
//            } else if (token.equals(JsonToken.END_OBJECT)) {
//                reader.endObject();
//            if (token.equals(JsonToken.END_ARRAY)) {
//                reader.endArray();
//                break;
//            } else {
            if (token.equals(JsonToken.NAME)) {
                String name = reader.nextName();
                if (name.equals("value")) {
                    cweIds.add(reader.nextString());
                } else {
                    reader.skipValue();
                }
//                }
            }
        }
        return cweIds;
    }
//
//    private void handleJsonArray(JsonReader reader) throws IOException {
//        reader.beginArray();
//        while (true) {
//            JsonToken token = reader.peek();
//            if (token.equals(JsonToken.END_ARRAY)) {
//                reader.endArray();
//                break;
//            } else if (token.equals(JsonToken.BEGIN_OBJECT)) {
//                handleJsonObject(reader);
//            } else if (token.equals(JsonToken.END_OBJECT)) {
//                reader.endObject();
//            } else if (token.equals(JsonToken.BEGIN_ARRAY)) {
//                reader.beginArray();
//            } else {
//                reader.skipValue();
//            }
//        }
//    }

    private Map<String, ArrayList<String>> writeFullDataStore() {
        // TODO handle writing entire file to store instead of filtered values for SBOM

        return new HashMap<>();
    }
}
