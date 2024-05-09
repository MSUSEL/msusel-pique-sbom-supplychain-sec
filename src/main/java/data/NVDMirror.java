package data;

import data.cveData.CveDetails;
import data.cveData.Vulnerability;
import data.dao.IDao;
import data.dao.NvdBulkOperationsDao;
import data.dao.NvdMetaDataDao;
import data.interfaces.HTTPMethod;
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
    private final IDao<List<CveDetails>> nvdBulkOperationsDao = new NvdBulkOperationsDao();
    private final NvdMetaDataDao metaDataDao = new NvdMetaDataDao();

    public void getFullDataSet() {
        int cveCount = 1;

        for (int startIndex = 0; startIndex < cveCount; startIndex += Utils.NVD_MAX_PAGE_SIZE) {
            NVDRequest request = requestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKeyHeader, startIndex, Utils.NVD_MAX_PAGE_SIZE);
            NVDResponse response = request.executeRequest();
            cveCount = response.getCveResponse().getTotalResults(); // reset cveCount to correctly handle pagination
            ArrayList<Vulnerability> vulnerabilities = response.getCveResponse().getVulnerabilities();
            List<CveDetails> cves = new ArrayList<>();

            for(Vulnerability vulnerability : vulnerabilities) {
                cves.add(vulnerability.getCve());
            }
            nvdBulkOperationsDao.insert(cves);
            metaDataDao.replace(response.getCveResponse());

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
            }

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }
}

