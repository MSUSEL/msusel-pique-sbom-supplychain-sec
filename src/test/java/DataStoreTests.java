import com.mongodb.client.*;

import com.mongodb.client.model.Filters;
import data.*;
import data.ghsaData.CweNode;
import data.handlers.NvdCveMarshaler;
import data.interfaces.HTTPMethod;
import data.interfaces.JsonMarshaler;
import org.bson.BsonDocument;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import pique.utility.PiqueProperties;
import utilities.helperFunctions;
import org.bson.Document;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class DataStoreTests {
    private static Integer totalResults;
    Properties prop = PiqueProperties.getProperties();

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

    @Test
    public void testMongoCreation() {
        // Get a single cve from NVD
        List<String> apiKey = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path")));
        NVDRequestFactory nvdRequestFactory = new NVDRequestFactory();
        NVDResponse response;

        NVDRequest request = nvdRequestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKey, 0, 1);
        response = request.executeRequest();

        MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
        MongoDatabase database = mongoClient.getDatabase("nvdMirror");

        database.createCollection("vulnerabilities");
        database.listCollectionNames().forEach(System.out::println);

        MongoCollection<Document> collection = database.getCollection("vulnerabilities");
        NvdCveMarshaler nvdCveMarshaler = new NvdCveMarshaler();
        String cve = nvdCveMarshaler.marshalJson(response.getCveResponse());

        collection.insertOne(Document.parse(cve));
        BsonDocument queryFilter = Filters.eq("id", "CVE-1999-1471").toBsonDocument();
        Document document = collection.find(queryFilter).first();
        System.out.println(document);
    }
}
