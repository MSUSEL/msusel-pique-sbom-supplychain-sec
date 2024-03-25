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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class NVDResponseHandler implements ResponseHandler<JSONObject> {

    @Override
    public JSONObject handleResponse(HttpResponse httpResponse) throws IOException {
        Map<String, ArrayList<String>> cveMap = new HashMap<>();
        ArrayList<String> cweIds = new ArrayList<>();
        HttpEntity entity = httpResponse.getEntity();
        //Header encodingHeader = entity.getContentEncoding();
        String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
        JSONObject jsonResponse;    // This may be redundant with the JsonReader

        /*
         * Reads incoming json as a stream and processes on the fly
         * Adapted from https://www.tutorialspoint.com/gson/gson_streaming.htm
         */
        JsonReader reader = new JsonReader(new StringReader(json));
        handleJsonObject(cveMap, cweIds, reader);
        System.out.println(cveMap.get("CVE-1999-0095"));


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

    private Map<String, ArrayList<String>> mapCVEIdsToCWDIds(Map<String, ArrayList<String>> map, String cve, ArrayList<String> cweIds) {
        map.put(cve, cweIds);
        return map;
    }

    private void handleJsonObject(Map<String, ArrayList<String>> map, ArrayList<String> cweIds, JsonReader reader) throws IOException {
        String cveId = "";
        reader.beginObject();
        while (reader.hasNext()) {
            String name = reader.nextName();
            if
        }
    }


//        while (reader.hasNext()) {
//            JsonToken token = reader.peek();
//            // if json array or end of file, call handleJsonArray or return respectively
//            if (token.equals(JsonToken.BEGIN_ARRAY)) {
//                handleJsonArray(map, cweIds, reader);
//            } else if (token.equals(JsonToken.BEGIN_OBJECT)) {
//                    reader.beginObject();
//            } else if (token.equals(JsonToken.END_OBJECT)) {
//                reader.endObject();
//                // store values
//            } else {
//                // detect "CVE" and get id
//                if (token.equals(JsonToken.NAME)) {
//                    String name = reader.nextName();
//                    switch (name) {
//                        case "id":
//                            cveId = reader.nextString();
//                            break;
//                        case "weaknesses":
//                            String cweId = handleWeaknessesArray(reader);
//                            cweIds.add(cweId);
//                            reader.skipValue();
//                            break;
//                    }
//                } else {
//                    reader.skipValue();
//                }
//            }
//            if (!cveId.isEmpty()) {
//                mapCVEIdsToCWDIds(map, cveId, cweIds);
//            }
//        }
    }

    private void handleJsonArray(Map<String, ArrayList<String>> map, ArrayList<String> cweIds, JsonReader reader) throws IOException {
        reader.beginArray();

        while(true) {
            JsonToken token = reader.peek();
            if (token.equals(JsonToken.END_ARRAY)) {
                reader.endArray();
                break;
            } else if (token.equals(JsonToken.BEGIN_OBJECT)) {
                handleJsonObject(map, cweIds, reader);
            } else if (token.equals(JsonToken.END_OBJECT)) {
                reader.endObject();
            } else if (token.equals(JsonToken.BEGIN_ARRAY)) {
                handleJsonArray(map, cweIds, reader);
            } else {
                if (token.equals(JsonToken.NAME)) {
                    String name = reader.nextName();
                    if (name.equals("value")) {
                        System.out.println(name);
                    }
            }
        }
    }

    private String handleWeaknessesArray(JsonReader reader) throws IOException {
        String cweId = "";
        reader.beginArray();
        JsonToken token = reader.peek();
        while (reader.hasNext()) {
            if (token.equals(JsonToken.NAME)) {
                if (reader.nextName().equals("description")) {
                    cweId = handleWeakenessDescriptionArray(reader);
                }
            }
        }
        reader.endArray();
        return cweId;
    }

    private String handleWeakenessDescriptionArray(JsonReader reader) throws IOException {
        String cweId = "";
        reader.beginArray();
        JsonToken token = reader.peek();
        while (reader.hasNext()) {
            if (token.equals(JsonToken.NAME)) {
                if (reader.nextName().equals("value")) {
                    cweId = reader.nextString();
                }
            }
        }
        reader.endArray();
        return cweId;
    }

    private Map<String, ArrayList<String>> writeFullDataStore() {
        // TODO handle writing entire file to store instead of filtered values for SBOM

        return new HashMap<>();
    }
}
