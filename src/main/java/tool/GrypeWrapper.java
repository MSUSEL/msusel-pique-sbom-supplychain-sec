/**
 * MIT License
 * Copyright (c) 2019 Montana State University Software Engineering Labs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package tool;

import data.GHSARequest;
import data.GHSAResponse;
import data.GraphQlQueries;
import data.Utils;
import data.cveData.CveDetails;
import data.cveData.Weakness;
import data.cveData.WeaknessDescription;
import data.dao.IDao;
import data.dao.NvdDao;
import data.ghsaData.CweNode;
import data.interfaces.HTTPMethod;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.model.Finding;
import pique.utility.PiqueProperties;
import toolOutputObjects.GrypeVulnerability;
import utilities.helperFunctions;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

/**
 * CODE TAKEN FROM PIQUE-BIN-DOCKER AND MODIFIED FOR PIQUE-SBOM-SUPPLYCHAIN-SEC.
 *
 * This tool wrapper will run and analyze the output of the tool Grype.
 * When parsing the output of the tool, a command line call to run a Python script is made. This script is responsible for translating from
 * CVE number to the CWE it is categorized as by the NVD. The python script requires a github api token.
 * @author Eric O'Donoghue
 *
 */
public class GrypeWrapper extends Tool implements ITool  {
	private static final Logger LOGGER = LoggerFactory.getLogger(GrypeWrapper.class);
	private final String githubTokenPath;

	public GrypeWrapper(String githubTokenPath) {
		super("grype", null);
		this.githubTokenPath = githubTokenPath;
	}

	/**
	 * Runs grype through the command line on the given SBOM and saves results to a temporary file.
	 *
	 * @param projectLocation The path to an SBOM file for the desired solution of project to analyze
	 * @return The path to the analysis results file
	 */
	@Override
	public Path analyze(Path projectLocation) {
		LOGGER.info(this.getName() + "  Analyzing "+ projectLocation.toString());

		// clear previous results
		File tempResults = new File(System.getProperty("user.dir") + "/out/grype.json");
		tempResults.delete();
		tempResults.getParentFile().mkdirs();

		// command for running Grype on the command line
		String[] cmd = {"grype",
				projectLocation.toAbsolutePath().toString(), // product under analysis path
				"--output", "sarif",
				"--quiet",
				"--file",tempResults.toPath().toAbsolutePath().toString()}; // output path
		LOGGER.info(Arrays.toString(cmd));

		// runs the command built above and captures the output, grype itself will handle the file saving
		try {
			helperFunctions.getOutputFromProgram(cmd,LOGGER);
		} catch (IOException  e) {
			LOGGER.error("Failed to run Grype");
			LOGGER.error(e.toString());
			e.printStackTrace();
		}

		return tempResults.toPath();
	}

	/**
	 * Parses output of tool from analyze().
	 *
	 * @param toolResults location of the results, output by analyze()
	 * @return A Map<String,Diagnostic> with findings from the tool attached. Returns null if tool failed to run.
	 */
	@Override
	public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
		String results = "";

		System.out.println(this.getName() + " Parsing Analysis...");
		LOGGER.debug(this.getName() + " Parsing Analysis...");

		// find all diagnostic nodes associated with Grype
		Map<String, Diagnostic> diagnostics = helperFunctions.initializeDiagnostics(this.getName());

		// TODO double check / document our conventions for log levels
		// read and process Grype output
		try {
			results = helperFunctions.readFileContent(toolResults);
		} catch (IOException e) {
			LOGGER.info("No results to read from Grype.");
		}
		JSONArray vulnerabilities = getVulnerabilitiesFromGrypeOutput(results);
		if (vulnerabilities != null) {
			// TODO should we check if grypeVulnerabilities was processed successfully? The addDiagnostics() call would simply return without adding any nodes in the event that no GrypeVulnerability objects were created.
			ArrayList<GrypeVulnerability> grypeVulnerabilities = processGrypeVulnerabilities(vulnerabilities);

			// Add results to PIQUE tree
			addDiagnostics(grypeVulnerabilities, diagnostics);
		} else {
			LOGGER.warn("Vulnerability array was empty.");
		}

		return diagnostics;
	}

	/**
	 * Initializes the tool by installing it through python pip from the command line.
	 *
	 * Because of dockerization this is no longer needed and currently just prints the version.
	 * Method must be left because it must be overridden.
	 */
	@Override
	public Path initialize(Path toolRoot) {
		final String[] cmd = {"grype", "version"};

		try {
			helperFunctions.getOutputFromProgram(cmd, LOGGER);
		} catch (IOException e) {
			e.printStackTrace();
			LOGGER.error("Failed to initialize " + this.getName());
			LOGGER.error(e.getStackTrace().toString());
		}

		return toolRoot;
	}

	/**
	 * Gets the vulnerabilities array from the complete Grype results
	 *
	 * @param results Grype tool output in String format
	 * @return a jsonArray of Grype results or null if no vulnerabilities are found
	 */
	private JSONArray getVulnerabilitiesFromGrypeOutput(String results) {
		try {
			JSONObject jsonResults = new JSONObject(results);
			return jsonResults.optJSONArray("runs").optJSONObject(0).optJSONObject("tool").optJSONObject("driver").optJSONArray("rules");
		} catch (JSONException e) {
			LOGGER.warn("Unable to read results from Grype");
        }

		return null;
    }

	/**
	 * Processes the JSONArray of Grype vulnerabilities into java objects.
	 * This makes it easier to store and process data into Findings later.
	 * Once created, these objects are read-only.
	 *
	 * @param jsonVulns JSONArray of Grype vulnerabilities
	 * @return ArrayList of GrypeVulnerability java objects
	 */
	private ArrayList<GrypeVulnerability> processGrypeVulnerabilities(JSONArray jsonVulns) {
		// TODO given that this method has the potential to make API calls, performance could become an issue
		// TODO consider Async calls to DB and GitHub API? Would that even help?
		ArrayList<GrypeVulnerability> grypeVulnerabilities = new ArrayList<>();

		try {
			for (int i = 0; i < jsonVulns.length(); i++) {
				ArrayList<String> cwes = new ArrayList<>();
				JSONObject jsonFinding = (JSONObject) jsonVulns.get(i);
				String cveId = jsonFinding.get("id").toString();

				if(cveId.contains("GHSA")) {
					cwes.addAll(retrieveGhsaCwes(cveId));	// TODO How many GHSAs are likely? Rate limit issues? Batch API calls? Could even start collecting in DB
				} else {
					cwes.addAll(retrieveNvdCwes(cveId));    // TODO Consider batch processing for large number of cwes?
				}

				String findingSeverity = ((JSONObject) jsonFinding.get("properties")).get("security-severity").toString();
				grypeVulnerabilities.add(new GrypeVulnerability(cveId, cwes, helperFunctions.severityToInt(findingSeverity)));
			}
		} catch (JSONException e) {
			LOGGER.warn("Unable to parse json. ", e);
			// TODO should we not throw something here? I'm guessing we're letting the program continue to execute intentionally?
		}

		return grypeVulnerabilities;
	}

	/**
	 * Retrieves CWE list for given CVE from the GitHub Vulnerabiity Database
	 *
	 * @param cveId one cve identified in the Grype tool output
	 * @return all associated CWEs for the cveId
	 */
	private ArrayList<String> retrieveGhsaCwes(String cveId) {
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
		IDao<CveDetails> nvdDao = new NvdDao();
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

	/**
	 * Builds Finding and Diagnostic objects from the list of GrypeVulnerabilities generated previously.
	 * Adds the new Diagnostics to the PIQUE tree.
	 *
	 * @param grypeVulnerabilities ArrayList of GrypeVulnerability objects representing Output from Grype
	 * @param diagnostics Map of diagnostics for Grype output
	 */
	private void addDiagnostics(ArrayList<GrypeVulnerability> grypeVulnerabilities, Map<String, Diagnostic> diagnostics) {
		for (GrypeVulnerability grypeVulnerability : grypeVulnerabilities) {
			// TODO I'm guessing there are some formatting issues with the CVE name here. Need some actual output/diagnostics to check.
			Diagnostic diag = diagnostics.get(grypeVulnerability.getCve() + "Grype Diagnostic");
			if (diag == null) {
				diag = diagnostics.get("CWE-other Grype Diagnostic");
				LOGGER.warn("CVE with CWE outside of CWE-699 found.");
			}
			Finding finding = new Finding("", 0, 0, grypeVulnerability.getSeverity());
			finding.setName(grypeVulnerability.getCve());
			diag.setChild(finding);
		}
	}
}
