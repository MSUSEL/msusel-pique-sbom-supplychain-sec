package data;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;


public class NVDDataStore {
    private Map<String, String[]> nvdDataStore = new HashMap<>();
    String baseURI = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    public Map<String, String[]> getNvdDataStore() {
        return nvdDataStore;
    }

    public void initializeDataStore() throws IOException, URISyntaxException, InterruptedException {
        // TODO initialize and fill the data store
        HttpGet request = new HttpGet("https://services.nvd.nist.gov/rest/json/cves/2.0");
        NVDResponseHandler handler = new NVDResponseHandler();


        //Integer startIndex = 0;
        int totalResults = 1;   // This value gets set by response header in subsequent calls
        Integer resultsPerPage = 2000;


        for(Integer i = 0; i < totalResults; i += resultsPerPage){

            URI uri = new URIBuilder(baseURI)
                    .addParameter("resultsPerPage", resultsPerPage.toString())
                    .addParameter("startIndex", i.toString())
                    .build();
            request.setURI(uri);
            request.setHeader("apiKey", "c24cc024-976f-4fa6-8d0e-90f9c78a1075");

            try (CloseableHttpClient client = HttpClients.createDefault();
                 CloseableHttpResponse response = client.execute(request)) {

                JSONObject jsonResponse = handler.handleResponse(response);
                if (i == 0) {
                    totalResults = jsonResponse.getInt("totalResults");
                }


                nvdDataStore = NVDResponseHandler.getCveCweMap();
            } catch (JSONException e) {
                throw new RuntimeException(e);
            }
            Thread.sleep(500);
        }

    }

//    private ArrayList<String> parseCWEIds(JSONObject filteredResponse) throws JSONException {
//        JSONObject cve = filteredResponse.getJSONObject("cve");
//        String cveId = cve.getString("id");
//        // TODO This nested json array parsing seems exceptionally fragile
//        JSONArray descriptions = cve.getJSONArray("weaknesses").getJSONArray(2);
//        ArrayList<String> cweIds = new ArrayList<>();
//
//        for(int i = 0; i < descriptions.length(); i++) {
//            JSONObject o = descriptions.getJSONObject(i);
//            cweIds.add(o.getString("value"));
//        }
//
//        return cweIds;
//    }

    private String buildRequest() {
        // TODO encode correct request
        String request = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218";
        return request;
    }
}
