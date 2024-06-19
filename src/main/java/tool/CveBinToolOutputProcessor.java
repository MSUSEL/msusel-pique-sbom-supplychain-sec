package tool;

import data.GHSARequest;
import data.GHSAResponse;
import data.Utils;
import data.cveData.CveDetails;
import data.cveData.Weakness;
import data.cveData.WeaknessDescription;
import data.dao.CveDetailsDao;
import data.dao.IDao;
import data.ghsaData.CweNode;
import data.interfaces.HTTPMethod;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.model.Diagnostic;
import pique.model.Finding;
import pique.utility.PiqueProperties;
import toolOutputObjects.RelevantVulnerabilityData;
import utilities.helperFunctions;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CveBinToolOutputProcessor implements IOutputProcessor<RelevantVulnerabilityData> {
    private static final Logger LOGGER = LoggerFactory.getLogger(TrivyGrypeOutputProcessor.class);

    /**
     * Gets the vulnerabilities array from the complete Tool results
     *
     * @param results tool output in String format
     * @return a jsonArray of Tool results or null if no vulnerabilities are found
     */
    @Override
    public JSONArray getVulnerabilitiesFromToolOutput(String results, String toolName) {
        try {
            JSONArray vulnerabilities = new JSONArray(results); // Assuming jsonData is a string containing the JSON array.
            JSONArray extractedVulnerabilities = new JSONArray();
            for (int i = 0; i < vulnerabilities.length(); i++) {
                JSONObject vulnerability = vulnerabilities.getJSONObject(i); // Directly accessing the vulnerability object.
                if (vulnerability != null)
                    extractedVulnerabilities.put(vulnerability); // Adding directly to the result array if it exists.
            }
            return extractedVulnerabilities;
        }
        catch (JSONException e) {
            LOGGER.warn("Unable to read results from {} output", toolName);
        }

        return null;
    }

    /**
     * Processes the JSONArray of tool output vulnerabilities into java objects.
     * This makes it easier to store and process data into Findings later.
     * Once created, these objects are read-only.
     *
     * @param jsonVulns JSONArray of tool output vulnerabilities
     * @return ArrayList of RelevantVulnerabilityData java objects
     */
    @Override
    public ArrayList<RelevantVulnerabilityData> processToolVulnerabilities(JSONArray jsonVulns, String toolName) {
        ArrayList<RelevantVulnerabilityData> toolVulnerabilities = new ArrayList<>();

        try {
            for (int i = 0; i < jsonVulns.length(); i++) {
                JSONObject jsonFinding = (JSONObject) jsonVulns.get(i);
                String vulnId = jsonFinding.get("cve_number").toString();
                String findingSeverity = jsonFinding.optString("severity");
                // String findingSeverity = jsonFinding.optString("score");
                //String vulnId = formatVulnerabilityId(rawId);
                ArrayList<String> cwes = vulnId.contains("GHSA") ? retrieveGhsaCwes(vulnId) : retrieveNvdCwes(vulnId);
                if (!cwes.isEmpty()) {
                    toolVulnerabilities.add(new RelevantVulnerabilityData(vulnId, cwes, helperFunctions.severityToInt(findingSeverity)));
                }
            }
        } catch (JSONException e) {
            // This intentionally lacks a throw.
            // No json result is a valid program state and is handled elsewhere
            LOGGER.warn("Unable to parse json. ", e);
        }

        return toolVulnerabilities;
    }

    /**
     * Builds Finding and Diagnostic objects from the list of ToolVulnerabilities generated previously.
     * Adds the new Diagnostics to the PIQUE tree.
     *
     * @param toolVulnerabilities ArrayList of RelevantVulnerabilityData objects representing Output from Tool
     * @param diagnostics Map of diagnostics for Tool output
     */
    // TODO This void method is a little confusing - improve?
    @Override
    public void addDiagnostics(ArrayList<RelevantVulnerabilityData> toolVulnerabilities, Map<String, Diagnostic> diagnostics, String toolName) {
        for (RelevantVulnerabilityData relevantVulnerabilityData : toolVulnerabilities) {
            Diagnostic diag = diagnostics.get(relevantVulnerabilityData.getCwe().get(0) + toolName);
            if (diag == null) {
                diag = diagnostics.get("CWE-other" + toolName);
                LOGGER.warn("CVE with CWE outside of CWE-699 found.");
            }
            Finding finding = new Finding("", 0, 0, relevantVulnerabilityData.getSeverity());
            finding.setName(relevantVulnerabilityData.getCve());
            diag.setChild(finding);
        }
    }

    /**
     * Retrieves CWE list for given CVE from the GitHub Vulnerabiity Database
     *
     * @param cveId one cve identified in the tool output
     * @return all associated CWEs for the cveId
     */
    private ArrayList<String> retrieveGhsaCwes(String cveId) {
        // TODO How many GHSAs are likely? Rate limit issues? Batch API calls?
        ArrayList<String> cwes = new ArrayList<>();

        Properties prop = PiqueProperties.getProperties();	// TODO this might already been injected at the class level
        String githubToken = helperFunctions.getAuthToken(prop.getProperty("github-token-path"));

        // format GitHub Vulnerability API request
        String query = helperFunctions.formatSecurityAdvisoryQuery(cveId);
        String authHeader = String.format("Bearer %s", githubToken);
        List<String> headers = Arrays.asList("Content-Type", "application/json", "Authorization", authHeader);

        // Make API request
        GHSARequest ghsaRequest = new GHSARequest(HTTPMethod.POST, Utils.GHSA_URI, headers, query);
        GHSAResponse ghsaResponse = ghsaRequest.executeRequest();

        // format CWEs and return
        for(CweNode cweNode : ghsaResponse.getSecurityAdvisory().getCwes().getNodes()) {
            cwes.add(cweNode.getCweId());
        }

        return cwes;
    }

    /**
     * Retrieves the given CVE's associated CWEs from the NVDMirror database
     *
     * @param cve A cveId corresponding to a valid NVD Vulnerability
     * @return ArrayList of CWEs (descriptions) associated with the given CVE
     */
    private ArrayList<String> retrieveNvdCwes(String cve) {
        // TODO add data access strategy: NVDMirror or API call
        // TODO Consider batch processing for large number of cwes?
        IDao<CveDetails> cveDetailsDao = new CveDetailsDao();
        ArrayList<String> descriptions = new ArrayList<>();

        CveDetails cveDetails = cveDetailsDao.getById(cve);
        if (cveDetails.getWeaknesses() != null) {
            for (Weakness weakness : cveDetails.getWeaknesses()) {
                for (WeaknessDescription description : weakness.getDescription()) {
                    if (description.getValue().equals("NVD-CWE-Other") || description.getValue().equals("NVD-CWE-noinfo")) {
                        descriptions.add("CWE-unknown");
                    } else {
                        descriptions.add(description.getValue());
                    }
                }
            }
        }

        return descriptions;
    }

    private String formatVulnerabilityId(String id) {
        Pattern pattern = Pattern.compile("CVE-\\d{3,4}-\\d{3,4}(?=.*)");
        Matcher matcher = pattern.matcher(id);

        return matcher.find() ? id.substring(0, matcher.end()) : "";
    }
}
