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
import utilities.helperFunctions;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.regex.*;

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
		System.out.println(this.getName() + " Parsing Analysis...");
		LOGGER.debug(this.getName() + " Parsing Analysis...");

		// find all diagnostic nodes associated with Grype
		Map<String, Diagnostic> diagnostics = helperFunctions.initializeDiagnostics(this.getName());

		// read Grype results file
		String results = "";
		try {
			results = helperFunctions.readFileContent(toolResults);
		} catch (IOException e) {
			LOGGER.info("No results to read from Grype.");
		}

		ArrayList<String> cveList = new ArrayList<String>();
		ArrayList<Integer> severityList = new ArrayList<Integer>();

		try {
			// complex json access to list of findings in Grype sarif results
			JSONObject jsonResults = new JSONObject(results);
			JSONArray vulnerabilities = jsonResults.optJSONArray("runs").optJSONObject(0).optJSONObject("tool").optJSONObject("driver").optJSONArray("rules");

			// if vulnerabilities is null we had no findings, thus return
			if (vulnerabilities == null) {
				return diagnostics;
			}

			for (int i = 0; i < vulnerabilities.length(); i++) {
				JSONObject jsonFinding = (JSONObject) vulnerabilities.get(i);

				// extract CVE id and severity score from the current finding
				String findingName = jsonFinding.get("id").toString();
				String findingSeverity = ((JSONObject) jsonFinding.get("properties")).get("security-severity").toString();
				severityList.add(helperFunctions.severityToInt(findingSeverity));
				cveList.add(findingName);
			}

			// TODO: change CVE_to_CWE script to return both the CVE and CWE, do this by printing CVE,CWE then
			// maps CVEs to corresponding CWEs in CWE-699. If a mapped CWE is outside CWE-699 the CVE will
			// be mapped to CWE-other (logic for this below not in python script), if a mapping can not be found or no
			// mapping exists we map the CVE to CWE-unknown.
			String[] findingNames = helperFunctions.getCWE(cveList, this.githubTokenPath);
			for (int i = 0; i < findingNames.length; i++) {
				// CWE-unknown or CWE within CWE-699 family
				Diagnostic diag = diagnostics.get((findingNames[i]+" Grype Diagnostic"));

				// CWE not in CWE-699
				if (diag == null) {
					diag = diagnostics.get("CWE-other Grype Diagnostic");
					LOGGER.warn("CVE with CWE outside of CWE-699 found.");
				}

				// set current finding (CVE or GHSA) as a child of the corresponding diagnostic node
				Finding finding = new Finding("",0,0,severityList.get(i));
				finding.setName(cveList.get(i));
				diag.setChild(finding);
			}
		} catch (JSONException e) {
			LOGGER.warn("Unable to read results from Grype");
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
}
