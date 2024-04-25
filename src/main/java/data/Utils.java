package data;

import data.interfaces.HTTPMethod;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.utility.PiqueProperties;
import utilities.helperFunctions;

import java.util.*;

/**
 *  Utility class for helper methods related to Data Access
 */
public class Utils {
    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

    // constants for use with data access
    public static final String NVD_BASE_URI = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    public static final String GHSA_URI = "https://api.github.com/graphql";
    public static final int NVD_MAX_PAGE_SIZE = 2000;
    public static final String GHSA_SECURITY_ADVISORY_QUERY = "query { securityAdvisory(ghsaId: \"%s\") { ghsaId summary cwes(first : 1) { nodes { cweId } } } }";


    /**
     * Gets the total number of CSVs currently listed in the NVD
     * This is necessary for requesting all the NVD data
     * as is required by some PIQUE extensions
     * @return Integer representing total number of CVEs in NVD
     */
    public static Integer getCSVCount() {
        Properties prop = PiqueProperties.getProperties();
        List<String> apiKey = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path")));
        NVDRequestFactory nvdRequestFactory = new NVDRequestFactory();
        NVDResponse response;

        NVDRequest request = nvdRequestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKey, 0, 1);
        response = request.executeRequest();
        int status = response.getStatus();

        // TODO handle if this call fails
        if (status >= 200 && status < 300) {
            return response.getCveResponse().getTotalResults();
        } else {
            LOGGER.info("Response status: {}", status);
            return -1;
        }
    }

    /**
     * Headers need to be formatted into an array of Header Objects.
     * The constructor for BaseRequest passes headers as strings for ease of use.
     * This method resolves those strings to Header objects
     * @param headerStrings List of header key,value pairs as strings
     * @return array of Header objects
     */
    public static Header[] resolveHeaders(List<String> headerStrings) {
        int size = headerStrings.size() / 2;
        Header[] headers = new Header[size];
        for (int i = 0; i < headerStrings.size() - 1; i += 2) {
            headers[i / 2] = new BasicHeader(headerStrings.get(i), headerStrings.get(i + 1));
        }
        return headers;
    }
}
