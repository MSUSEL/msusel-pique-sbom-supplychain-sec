import data.*;
import data.cveData.CveDetails;
import data.cveData.Vulnerability;
import data.dao.IDao;
import data.dao.NvdBulkOperationsDao;
import data.dao.CveDetailsDao;
import data.dao.NvdMetaDataDao;
import data.ghsaData.CweNode;
import data.interfaces.HTTPMethod;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import pique.utility.PiqueProperties;
import utilities.helperFunctions;

import java.io.IOException;
import java.util.*;

import static org.junit.Assert.*;

public class DataStoreTests {
    private static Integer totalResults;
    Properties prop = PiqueProperties.getProperties();
    private IDao<CveDetails> nvdDao = new CveDetailsDao();

    @Test
    public void testDataStoreFullBuild() {
        NVDMirror mirror = new NVDMirror();
        mirror.getFullDataSet();
    }

    @Test
    public void testGhsaRequest() throws JSONException {
        String ghsaId = "GHSA-vh2m-22xx-q94f";

        // Define the query string
        JSONObject jsonBody = new JSONObject();
        jsonBody.put("query", GraphQlQueries.GHSA_SECURITY_ADVISORY_QUERY);
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
    public void testMongoOnServer() {
        NvdMetaDataDao dao = new NvdMetaDataDao();
        NVDRequestFactory nvdRequestFactory = new NVDRequestFactory();
        List<List<String>> creds = new ArrayList<>();

        NVDRequest request = nvdRequestFactory.createNVDRequest(
                HTTPMethod.GET,
                Utils.NVD_BASE_URI,
                Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path"))),
                0,
                1);
        NVDResponse nvdResponse = request.executeRequest();

        try {
            creds = Utils.getMongoCredentials();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        assertFalse(creds.isEmpty());
    }

//    @Test
//    public void testMongoCreation() {
//        // Get a single cve from NVD
//        List<String> apiKey = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path")));
//        NVDRequestFactory nvdRequestFactory = new NVDRequestFactory();
//        NVDResponse response;
//
//        NVDRequest request = nvdRequestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKey, 0, 1);
//        response = request.executeRequest();
//
//        MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
//        MongoDatabase database = mongoClient.getDatabase("nvdMirror");
//
//        database.createCollection("vulnerabilities");
//        //database.listCollectionNames().forEach(System.out::println);
//
//        MongoCollection<Document> collection = database.getCollection("vulnerabilities");
//        NvdCveMarshaller nvdCveMarshaler = new NvdCveMarshaller();
//        String cve = nvdCveMarshaler.marshalCve(response.getCveResponse().getVulnerabilities().get(0).getCve());
//
//        collection.insertOne(Document.parse(cve));
//        BsonDocument queryFilter = Filters.eq("id", "CVE-1999-1471").toBsonDocument();
//        Document document = collection.find(queryFilter).first();
//        System.out.println(document);
//    }
//
//    @Test
//    public void testMongoQuery() {
//        MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
//        MongoDatabase database = mongoClient.getDatabase("nvdMirror");
//        MongoCollection<Document> collection = database.getCollection("vulnerabilities");
//        BsonDocument queryFilter = Filters.eq("id", "CVE-1999-0095").toBsonDocument();
//        Document document = collection.find(queryFilter).first();
//        System.out.println(document);
//    }

    @Test
    public void testDaoQuery() {
        nvdDao = new CveDetailsDao();
        CveDetails cve = nvdDao.getById("CVE-1999-0095");

        assertNotNull(cve.getId());
        assertEquals("NVD-CWE-Other", cve.getWeaknesses().get(0).getDescription().get(0).getValue());

        cve = nvdDao.getById("CVE-1999-1554");
        assertEquals("NVD-CWE-Other", cve.getWeaknesses().get(0).getDescription().get(0).getValue());

    }

    @Test
    public void testDaoInsert() {
        List<String> apiKey = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path")));
        NVDRequestFactory nvdRequestFactory = new NVDRequestFactory();
        NVDResponse response;

        NVDRequest request = nvdRequestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKey, 0, 1);
        response = request.executeRequest();

        nvdDao.insert(response.getCveResponse().getVulnerabilities().get(0).getCve());

    }

    @Test
    public void testDaoInsertMany() {
        NvdBulkOperationsDao nvdBulkOperationsDao = new NvdBulkOperationsDao();
        List<String> apiKey = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path")));
        NVDRequestFactory nvdRequestFactory = new NVDRequestFactory();
        NVDResponse response;

        NVDRequest request = nvdRequestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKey, 0, 2000);
        response = request.executeRequest();
        List<CveDetails> cves = new ArrayList<>();

        for (Vulnerability vulnerability : response.getCveResponse().getVulnerabilities()) {
            cves.add(vulnerability.getCve());
        }

        nvdBulkOperationsDao.insert(cves);
    }

    @Test
    public void testMetaDataInsert() {
        List<String> apiKey = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path")));
        NVDRequestFactory nvdRequestFactory = new NVDRequestFactory();
        NVDResponse response;

        NVDRequest request = nvdRequestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKey, 0, 1);
        response = request.executeRequest();

        NvdMetaDataDao nvdMetaDataDao = new NvdMetaDataDao();
        nvdMetaDataDao.insert(response.getCveResponse());
    }

    @Test
    public void testMetaDataReplace() {
        List<String> apiKey = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path")));
        NVDRequestFactory nvdRequestFactory = new NVDRequestFactory();
        NVDResponse response;

        NVDRequest request = nvdRequestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKey, 0, 1);
        response = request.executeRequest();

        NvdMetaDataDao nvdMetaDataDao = new NvdMetaDataDao();
        nvdMetaDataDao.replace(response.getCveResponse());
    }
}
