package data;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import data.cveData.CveDetails;
import data.cveData.Vulnerability;
import data.interfaces.HTTPMethod;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.utility.PiqueProperties;
import utilities.helperFunctions;

import java.util.*;

public class NVDMirror {
    private static final Logger LOGGER = LoggerFactory.getLogger(NVDMirror.class);
    private final Properties prop = PiqueProperties.getProperties();
    private final NVDRequestFactory requestFactory = new NVDRequestFactory();
    private final List<String> apiKeyHeader = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path")));

    // !!!  Data store implemented for testing - Remove before merging to master !!!
    @Getter
    private final Map<String, Vulnerability> dataStore = new HashMap<>();

    public void getFullDataSet() {
        int cveCount = 1;

        for (int startIndex = 0; startIndex < cveCount; startIndex += Utils.NVD_MAX_PAGE_SIZE) {
            NVDRequest request = requestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKeyHeader, startIndex, Utils.NVD_MAX_PAGE_SIZE);
            NVDResponse response = request.executeRequest();
            cveCount = response.getCveResponse().getTotalResults(); // reset cveCount to correctly handle pagination
            ArrayList<Vulnerability> vulnerabilities = response.getCveResponse().getVulnerabilities();
            for(Vulnerability vulnerability : vulnerabilities) {
                dataStore.put(vulnerability.getCve().getId(), vulnerability);
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                LOGGER.error("Thread interrupted", e);   // not sure if this is reachable in single-threaded code
                throw new RuntimeException(e);
            }
        }
    }

    // TODO refactor to DAO / parameterized DB connection / DI
    private void writeToMongo(CveDetails cveDetails) {
        MongoClient mongoClient = MongoClients.create("mongodb://localhost:27017");
        MongoDatabase database = mongoClient.getDatabase("nvdMirror");

        database.createCollection("vulnerabilities");
        database.listCollectionNames().forEach(System.out::println);
    }

    // TODO Test this method!!! This hasn't been run yet
    // ISO-8601 date/time format: [YYYY][“-”][MM][“-”][DD][“T”][HH][“:”][MM][“:”][SS][Z]
    public void updateNvdMirror(String lastModStartDate, String lastModEndDate) {
        NVDResponse response;
        int cveCount = 1;

        for (int startIndex = 0; startIndex < cveCount; startIndex += Utils.NVD_MAX_PAGE_SIZE) {
            NVDRequest request = requestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKeyHeader,
                    0, Utils.NVD_MAX_PAGE_SIZE, lastModStartDate, lastModEndDate);

            response = request.executeRequest();

            cveCount = response.getCveResponse().getTotalResults();
            ArrayList<Vulnerability> vulnerabilities = response.getCveResponse().getVulnerabilities();

            for (Vulnerability vulnerability : vulnerabilities) {
                dataStore.put(vulnerability.getCve().getId(), vulnerability);
            }

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }
}

