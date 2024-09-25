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
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import presentation.PiqueData;
import toolOutputObjects.RelevantVulnerabilityData;
import utilities.helperFunctions;

/**
 * CODE TAKEN FROM PIQUE-BIN-DOCKER AND MODIFIED FOR PIQUE-SBOM-SUPPLYCHAIN-SEC
 *
 * This class provides a wrapper for executing the Trivy tool, a comprehensive security scanner.
 * This class handles command-line execution of Trivy, result parsing, and diagnostic reporting within the PIQUE framework.
 *
 * @author Eric O'Donoghue
 */
public class TrivyWrapper extends Tool implements ITool  {
	private final PiqueData piqueData;
	private final String toolName = " Trivy Diagnostic";
	private static final Logger LOGGER = LoggerFactory.getLogger(TrivyWrapper.class);
	/**
	 * Constructs a TrivyWrapper instance.
	 *
	 */
	public TrivyWrapper(PiqueData piqueData) {
		super("trivy", null);
		this.piqueData = piqueData;
	}

	/**
	 * Executes the Trivy scanner via command line against an SBOM specified by the project location.
	 * Results are formatted as JSON and saved to a temporary file in the system's output directory.
	 *
	 * @param projectLocation The file path of the SBOM to be analyzed.
	 * @return The path to the file containing the analysis results.
	 * @throws IOException if there is an error executing the tool or handling file operations.
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
				"--format", "json",
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
	 * Parses the JSON output from Trivy and converts it into a map of Diagnostic objects,
	 * encapsulating the findings in a format usable by other components of the PIQUE framework.
	 * This method reads the tool's output, processes the vulnerabilities identified, and
	 * maps them to diagnostics based on their characteristics.
	 *
	 * @param toolResults The file path containing the results of the Trivy scan.
	 * @return A map containing the diagnostic results, or null if an error occurs during parsing or if the tool fails to run.
	 */
	@Override
	public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
		IOutputProcessor<RelevantVulnerabilityData> outputProcessor = new ToolOutputProcessor(new VulnerabilityService(piqueData, toolName));
		String results = "";

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
			List<RelevantVulnerabilityData> trivyVulnerabilities = outputProcessor.processToolVulnerabilities(vulnerabilities);
			outputProcessor.addDiagnostics(trivyVulnerabilities, diagnostics);
		} else {
			LOGGER.warn("Vulnerability array was empty.");
		}

		return diagnostics;
	}

	/**
	 * Prints the version of Trivy via a command line call. This method is a placeholder due to dockerization,
	 * which handles the actual installation and setup of the tool. Must remain implemented to fulfill interface obligations.
	 *
	 * @param toolRoot The root directory for the tool, not utilized in the current dockerized setup.
	 * @return The same toolRoot path passed as an argument.
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
