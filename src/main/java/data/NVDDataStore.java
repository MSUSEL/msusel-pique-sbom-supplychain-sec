package data;
import jdk.internal.util.xml.impl.Pair;
import org.apache.commons.io.Charsets;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.HttpEntity;
import org.apache.http.client.ResponseHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;


public class NVDDataStore {
    private HashMap<String, String> nvdDataStore = new HashMap<String, String>();
    String baseURI = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    public HashMap<String, String> getNvdDataStore() {
        return nvdDataStore;
    }

    public void initializeDataStore() throws IOException, URISyntaxException {
        // TODO initialize and fill the data store
        HttpGet request = new HttpGet("https://services.nvd.nist.gov/rest/json/cves/2.0");
        NVDResponseHandler handler = new NVDResponseHandler();


        Integer startIndex = 0;
        int totalResults = 20;   // This value gets set by response header in subsequent calls
        Integer resultsPerPage = 200;

        URI uri = new URIBuilder(request.getURI()).addParameter("resultsPerPage", resultsPerPage.toString())
                .addParameter("startIndex", startIndex.toString())
                .build();
        request.setURI(uri);
        request.setHeader("apiKey", "c24cc024-976f-4fa6-8d0e-90f9c78a1075");
        for(int i = 0; i < totalResults; i += resultsPerPage){
            try (CloseableHttpClient client = HttpClients.createDefault();
                 CloseableHttpResponse response = client.execute(request)) {

                JSONObject jsonResponse = handler.handleResponse(response);
                totalResults = jsonResponse.getInt("totalResults");
                ArrayList<String> cweIds = parseCWEIds(jsonResponse);

                // TODO this loop needs to be fixed so all CVEs get parsed into CWEs
                nvdDataStore.put(jsonResponse.getJSONObject("cve").getString("id"), jsonResponse.)
            } catch (JSONException e) {
                throw new RuntimeException(e);
            }
        }

    }

    private ArrayList<String> parseCWEIds(JSONObject filteredResponse) throws JSONException {
        JSONObject cve = filteredResponse.getJSONObject("cve");
        String cveId = cve.getString("id");
        // TODO This nested json array parsing seems exceptionally fragile
        JSONArray descriptions = cve.getJSONArray("weaknesses").getJSONArray(2);
        ArrayList<String> cweIds = new ArrayList<>();

        for(int i = 0; i < descriptions.length(); i++) {
            JSONObject o = descriptions.getJSONObject(i);
            cweIds.add(o.getString("value"));
        }

        return cweIds;
    }

    private String buildRequest() {
        // TODO encode correct request
        String request = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218";
        return request;
    }
}
