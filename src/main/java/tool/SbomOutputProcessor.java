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
import toolOutputObjects.PiqueVulnerability;
import utilities.helperFunctions;

import java.util.*;

public class SbomOutputProcessor implements IOutputProcessor<PiqueVulnerability> {
    private static final Logger LOGGER = LoggerFactory.getLogger(SbomOutputProcessor.class);

    /**
     * Processes the JSONArray of tool output vulnerabilities into java objects.
     * This makes it easier to store and process data into Findings later.
     * Once created, these objects are read-only.
     *
     * @param jsonVulns JSONArray of tool output vulnerabilities
     * @return ArrayList of PiqueVulnerability java objects
     */
    @Override
    public ArrayList<PiqueVulnerability> processToolVulnerabilities(JSONArray jsonVulns) {
        // TODO given that this method has the potential to make API calls, performance could become an issue
        // TODO consider Async calls to DB and GitHub API? Would that even help?
        ArrayList<PiqueVulnerability> toolVulnerabilities = new ArrayList<>();

        try {
            for (int i = 0; i < jsonVulns.length(); i++) {
                JSONObject jsonFinding = (JSONObject) jsonVulns.get(i);
                String cveId = jsonFinding.get("id").toString();
                ArrayList<String> cwes = cveId.contains("GHSA") ? retrieveGhsaCwes(cveId) : retrieveNvdCwes(cveId);
                String findingSeverity = ((JSONObject) jsonFinding.get("properties")).get("security-severity").toString();
                toolVulnerabilities.add(new PiqueVulnerability(cveId, cwes, helperFunctions.severityToInt(findingSeverity)));
            }
        } catch (JSONException e) {
            // This intentionally lacks a throw. No Json results is a valid program state
            // and is handled elsewhere
            LOGGER.warn("Unable to parse json. ", e);
        }

        return toolVulnerabilities;
    }

    /**
     * Gets the vulnerabilities array from the complete Tool results
     *
     * @param results tool output in String format
     * @return a jsonArray of Tool results or null if no vulnerabilities are found
     */
    @Override
    public JSONArray getVulnerabilitiesFromToolOutput(String results) {
        try {
            JSONObject jsonResults = new JSONObject(results);
            return jsonResults.optJSONArray("runs").optJSONObject(0).optJSONObject("tool").optJSONObject("driver").optJSONArray("rules");
        } catch (JSONException e) {
            LOGGER.warn("Unable to read results from Tool");
        }

        return null;
    }

    /**
     * Builds Finding and Diagnostic objects from the list of ToolVulnerabilities generated previously.
     * Adds the new Diagnostics to the PIQUE tree.
     *
     * @param toolVulnerabilities ArrayList of PiqueVulnerability objects representing Output from Tool
     * @param diagnostics Map of diagnostics for Tool output
     */
    @Override
    public void addDiagnostics(ArrayList<PiqueVulnerability> toolVulnerabilities, Map<String, Diagnostic> diagnostics) {
        for (PiqueVulnerability piqueVulnerability : toolVulnerabilities) {
            // TODO I'm guessing there are some formatting issues with the CVE name here. Need some actual output/diagnostics to check.
            Diagnostic diag = diagnostics.get(piqueVulnerability.getCve() + "Tool Diagnostic");
            if (diag == null) {
                diag = diagnostics.get("CWE-other Tool Diagnostic");
                LOGGER.warn("CVE with CWE outside of CWE-699 found.");
            }
            Finding finding = new Finding("", 0, 0, piqueVulnerability.getSeverity());
            finding.setName(piqueVulnerability.getCve());
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
        // TODO How many GHSAs are likely? Rate limit issues? Batch API calls? Could even start collecting in DB
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
        IDao<CveDetails> nvdDao = new CveDetailsDao();
        ArrayList<String> descriptions = new ArrayList<>();

        for (Weakness weakness : nvdDao.getById(cve).getWeaknesses()) {
            for (WeaknessDescription description : weakness.getDescription()) {
                if (description.getValue().equals("NVD-CWE-Other") || description.getValue().equals("NVD-CWE-noinfo")) {
                    descriptions.add("CWE-unknown");
                } else {
                    descriptions.add(description.getValue());
                }
            }
        }

        return descriptions;
    }
}