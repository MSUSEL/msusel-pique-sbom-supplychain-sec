import data.*;
import data.ghsaData.CweNode;
import data.interfaces.HTTPMethod;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import pique.utility.PiqueProperties;
import utilities.helperFunctions;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class DataStoreTests {
    private static Integer totalResults;
    Properties prop = PiqueProperties.getProperties();
    /**
     * Call to NVD API to get total number of CVE's in database.
     * This number is updated constantly and must be fetched before
     * every data store refresh
     */
//    @BeforeClass
//    public static void init() {
//        Integer totalResults;
//        totalResults = Utils.getCSVCount();
//        System.out.println(totalResults);
//    }

//    @Test
//    public void TestBasicNVDRequest() throws JSONException, URISyntaxException {
//        String baseURI = "https://services.nvd.nist.gov/rest/json/cves/2.0";
//        List<String> headers = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path"));
//        List<NameValuePair> params = new ArrayList<>();
//        params.add(new BasicNameValuePair("startIndex", "0"));
//        params.add(new BasicNameValuePair("resultsPerPage", "1"));
//
//        BaseRequest request = new NVDRequest(HTTPMethod.GET, baseURI, headers, params);
//        NVDResponse response = (NVDResponse) request.executeRequest();  // why do I need to cast this?

        //String firstValue = "NVD-CWE-Other";
//        ArrayList<String> value = store.getCWEByCve("CVE-1999-0095");
//        assertNotNull(value);
//        System.out.println(value);
//
//        value = store.getCWEByCve("CVE-1999-1391");
//        assertNotNull(value);
//        System.out.println(value);

//        Map<String, String[]> map = store.getGsonCveMap();
//        String[] values = map.get("CVE-1999-0095");
//        assertEquals(values[0], "NVD-CWE-Other");
//    }

    @Test
    public void testGetFirstCve() {
        int count = Utils.getCSVCount();
        System.out.println(count);
    }

    @Test
    public void testDataStoreFullBuild() {
        NVDMirror mirror = new NVDMirror();
        mirror.getFullDataSet();
        assert(100000 < mirror.getDataStore().size());
    }

    @Test
    public void testGhsaRequest() throws JSONException {
        String ghsaId = "GHSA-vh2m-22xx-q94f";

        // Define the query string
        JSONObject jsonBody = new JSONObject();
        jsonBody.put("query", Utils.GHSA_SECURITY_ADVISORY_QUERY);
        String query = jsonBody.toString();
        String formattedQuery = String.format(query, ghsaId);

        String githubToken = helperFunctions.getAuthToken(prop.getProperty("github-token-path"));
        String authHeader = String.format("Bearer %s", githubToken);
        List<String> headers = Arrays.asList("Content-Type", "application/json", "Authorization", authHeader);

        GHSARequest ghsaRequest = new GHSARequest(HTTPMethod.POST, Utils.GHSA_URI, headers, formattedQuery);
        GHSAResponse ghsaResponse = ghsaRequest.executeRequest();

        assertEquals(200, ghsaResponse.getStatus());
        assertEquals("GHSA-vh2m-22xx-q94f", ghsaResponse.getSecurityAdvisory().getGhsaId());
        assertEquals("Sensitive query parameters logged by default in OpenTelemetry.Instrumentation http and AspNetCore",
                ghsaResponse.getSecurityAdvisory().getSummary());

        ArrayList<CweNode> nodes = ghsaResponse.getSecurityAdvisory().getCwes().getNodes();
        assertEquals("CWE-201", nodes.get(0).getCweId());
    }
}
