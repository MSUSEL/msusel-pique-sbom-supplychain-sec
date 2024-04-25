package data;

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
    Properties prop = PiqueProperties.getProperties();

    // !!!  Data store implemented for testing - Remove before merging to master !!!
    @Getter
    private final Map<String, Vulnerability> dataStore = new HashMap<>();
    NVDRequestFactory requestFactory = new NVDRequestFactory();
    List<String> apiKeyheader = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path")));
    int cveCount;

    public NVDMirror() {
        cveCount = Utils.getCSVCount();
    }

    public void getFullDataSet() {
        NVDResponse response;

        for (int startIndex = 0; startIndex < cveCount; startIndex += Utils.NVD_MAX_PAGE_SIZE) {
            NVDRequest request = requestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKeyheader, startIndex, Utils.NVD_MAX_PAGE_SIZE);

            response = request.executeRequest();

            int status = response.getStatus();
            if (status >= 200 && status < 300) {
                ArrayList<Vulnerability> vulnerabilities = response.getCveResponse().getVulnerabilities();
                for(Vulnerability vulnerability : vulnerabilities) {
                    dataStore.put(vulnerability.getCve().getId(), vulnerability);
                }
            } else {
                LOGGER.info("Response status: {}", status);
            }

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                LOGGER.error("Thread interrupted", e);   // not sure if this is reachable in single-threaded code
                throw new RuntimeException(e);
            }
        }
    }

    // TODO Test this method!!! This hasn't been run yet
    // ISO-8601 date/time format: [YYYY][“-”][MM][“-”][DD][“T”][HH][“:”][MM][“:”][SS][Z]
    public void getUpdate(String lastModStartDate, String lastModEndDate) {
        NVDResponse response;
        for (int startIndex = 0; startIndex < cveCount; startIndex += Utils.NVD_MAX_PAGE_SIZE) {
            NVDRequest request = requestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKeyheader,
                    0, Utils.NVD_MAX_PAGE_SIZE, lastModStartDate, lastModEndDate);

            response = request.executeRequest();

            int status = response.getStatus();

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

