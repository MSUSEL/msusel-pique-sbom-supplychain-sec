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

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import toolOutputObjects.RelevantVulnerabilityData;
import utilities.helperFunctions;

/**
 * CODE TAKEN FROM PIQUE-BIN-DOCKER AND MODIFIED FOR PIQUE-SBOM-SUPPLYCHAIN-SEC.
 *
 * This tool wrapper will run and analyze the output of the tool Trivy.
 * When parsing the output of the tool, a command line call to run a Python script is made. This script is responsible for translating from
 * CVE number to the CWE it is categorized as by the NVD. The python script requires a github api token.
 * @author Eric O'Donoghue
 *
 */
public class TrivyWrapper extends Tool implements ITool  {
	private static final Logger LOGGER = LoggerFactory.getLogger(TrivyWrapper.class);
	private final String githubToken;

	public TrivyWrapper(String githubTokenPath) {
		super("trivy", null);
		this.githubToken = githubTokenPath;
	}

	/**
	 * Runs trivy through the command line on the given SBOM and saves results to a temporary file.
	 *
	 * @param projectLocation The path to an SBOM file for the desired solution of project to analyze
	 * @return The path to the analysis results file
	 */
	@Override
	public Path analyze(Path projectLocation) {
		LOGGER.info(this.getName() + "  Analyzing "+ projectLocation.toString());

		// clear previous results
		File tempResults = new File(System.getProperty("user.dir") + "/out/trivy.json");
		tempResults.delete();
		tempResults.getParentFile().mkdirs();

		// command for running Trivy on the command line
		String[] cmd = {"trivy",
				"sbom",
				"--format", "sarif",
				"--quiet",
				"--output",tempResults.toPath().toAbsolutePath().toString(), // output path
				projectLocation.toAbsolutePath().toString()}; // product under analysis path
		LOGGER.info(Arrays.toString(cmd));

		// runs the command built above and captures the output, trivy itself will handle the file saving
		try {
			helperFunctions.getOutputFromProgram(cmd,LOGGER);
		} catch (IOException  e) {
			LOGGER.error("Failed to run Trivy");
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
		IOutputProcessor<RelevantVulnerabilityData> outputProcessor = new SbomOutputProcessor();
		String results = "";
		String toolName = " Trivy Diagnostic";

		System.out.println(this.getName() + " Parsing Analysis...");
		LOGGER.debug(this.getName() + " Parsing Analysis...");

		// find all diagnostic nodes associated with Trivy
		Map<String, Diagnostic> diagnostics = helperFunctions.initializeDiagnostics(this.getName());

		// Read and process Trivy output
		try {
			results = helperFunctions.readFileContent(toolResults);
		} catch (IOException e) {
			LOGGER.info("No results to read from Trivy.");
		}

		JSONArray vulnerabilities = outputProcessor.getVulnerabilitiesFromToolOutput(results);
		if (vulnerabilities != null) {
			ArrayList<RelevantVulnerabilityData> trivyVulnerabilities = outputProcessor.processToolVulnerabilities(vulnerabilities);
			outputProcessor.addDiagnostics(trivyVulnerabilities, diagnostics, toolName);
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
		final String[] cmd = {"trivy", "version"};

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
