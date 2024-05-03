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

import data.cveData.CveDetails;
import data.cveData.Weakness;
import data.cveData.WeaknessDescription;
import data.dao.IDao;
import data.dao.NvdDao;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.model.Finding;
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

		// read Grype results file
		try {
			results = helperFunctions.readFileContent(toolResults);
		} catch (IOException e) {
			LOGGER.info("No results to read from Grype.");
		}

		JSONArray vulnerabilities = getVulnerabilitiesFromGrype(results);
		addDiagnostics(vulnerabilities, diagnostics);

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
	private JSONArray getVulnerabilitiesFromGrype(String results) {
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
		ArrayList<GrypeVulnerability> vulnerabilities = new ArrayList<>();

		try {
			for (int i = 0; i < jsonVulns.length(); i++) {
				JSONObject jsonFinding = (JSONObject) jsonVulns.get(i);
				String cveId = jsonFinding.get("id").toString();
				ArrayList<String> cwe = retrieveCwe(cveId);
				String findingSeverity = ((JSONObject) jsonFinding.get("properties")).get("security-severity").toString();
				vulnerabilities.add(new GrypeVulnerability(cveId, cwe, helperFunctions.severityToInt(findingSeverity)));
			}
		} catch (JSONException e) {
			LOGGER.warn("Unable to parse json. ", e);
		}

		return vulnerabilities;
	}

	/**
	 * Retrieves a CVE's associated CWE from the NVDMirror database
	 *
	 * @param cve A cveId corresponding to a valid NVD Vulnerability
	 * @return ArrayList of CWEs (descriptions) associated with the given CVE
	 */
	private ArrayList<String> retrieveCwe(String cve) {
		// TODO include GHSA vulnerabilities here
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
	 * @param vulnerabilities JSONArray of vulnerabilities (Output from Grype)
	 * @param diagnostics Map of diagnostics for Grype output
	 */
	private void addDiagnostics(JSONArray vulnerabilities, Map<String, Diagnostic> diagnostics) {
		ArrayList<GrypeVulnerability> grypeVulnerabilities;

		if (vulnerabilities != null) {
			grypeVulnerabilities = processGrypeVulnerabilities(vulnerabilities);
			for (GrypeVulnerability grypeVulnerability : grypeVulnerabilities) {
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
}
