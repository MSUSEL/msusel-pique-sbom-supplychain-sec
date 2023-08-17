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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

/**
 * CODE TAKEN FROM PIQUE-BIN-DOCKER AND MODIFIED FOR PIQUE-SBOM-CONTENT.
 * This tool wrapper will run and analyze the output of the tool.
 * When parsing the output of the tool, a command line call to run a Python script is made. This script is responsible for translating from
 * CVE number to the CWE it is categorized as by the NVD.
 * @author Eric O'Donoghue
 *
 */
public class TrivyWrapper extends Tool implements ITool  {
	private static final Logger LOGGER = LoggerFactory.getLogger(TrivyWrapper.class);
	private String nvdApiKey;
	private String githubToken;

	public TrivyWrapper(String nvdApiKeyPath, String githubTokenPath) {
		super("trivy", null);
		this.nvdApiKey = nvdApiKeyPath;
		this.githubToken = githubTokenPath;
	}

	// Methods
		/**
		 * @param projectLocation The path to a binary file for the desired solution of project to
		 *             analyze
		 * @return The path to the analysis results file
		 */
		@Override
		public Path analyze(Path projectLocation) {
			LOGGER.info(this.getName() + "  Analyzing "+ projectLocation.toString());
			File tempResults = new File(System.getProperty("user.dir") + "/out/trivy.json");
			tempResults.delete(); // clear out the last output. May want to change this to rename rather than delete.
			tempResults.getParentFile().mkdirs();

			String[] cmd = {"trivy",
					"sbom",
					"--format", "sarif",
					"--quiet",
					"--output",tempResults.toPath().toAbsolutePath().toString(),
					projectLocation.toAbsolutePath().toString()};
			LOGGER.info(Arrays.toString(cmd));
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
		 * parses output of tool from analyze().
		 *
		 * @param toolResults location of the results, output by analyze()
		 * @return A Map<String,Diagnostic> with findings from the tool attached. Returns null if tool failed to run.
		 */
		@Override
		public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
			System.out.println(this.getName() + " Parsing Analysis...");
			LOGGER.debug(this.getName() + " Parsing Analysis...");

			Map<String, Diagnostic> diagnostics = helperFunctions.initializeDiagnostics(this.getName());

			String results = "";

			try {
				results = helperFunctions.readFileContent(toolResults);
			} catch (IOException e) {
				LOGGER.info("No results to read from Trivy.");
			}

			ArrayList<String> cveList = new ArrayList<String>();
			ArrayList<Integer> severityList = new ArrayList<Integer>();

			try {
				JSONObject jsonResults = new JSONObject(results);
				JSONArray vulnerabilities = jsonResults.optJSONArray("runs").optJSONObject(0).optJSONObject("tool").optJSONObject("driver").optJSONArray("rules");

				for (int i = 0; i < vulnerabilities.length(); i++) {
					JSONObject jsonFinding = (JSONObject) vulnerabilities.get(i);
					//Need to change this for this tool. (should stay the same now when using SARIF format)
					String findingName = jsonFinding.get("id").toString();
					String findingSeverity = ((JSONObject) jsonFinding.get("properties")).get("security-severity").toString();
					severityList.add(this.severityToInt(findingSeverity));
					cveList.add(findingName);
				}

				// for testing only send through first 3 results
				//ArrayList<String> temp = new ArrayList<String>(cveList.subList(0, Math.min(3, cveList.size())));
				String[] findingNames = helperFunctions.getCWE(cveList, this.nvdApiKey, this.githubToken);
 				for (int i = 0; i < findingNames.length; i++) {
					Diagnostic diag = diagnostics.get((findingNames[i]+" Trivy Diagnostic"));
					if (diag == null) {
						//this means that either it is unknown, mapped to a CWE outside of the expected results, or is not assigned a CWE
						//We may want to treat this in another way.
						// My (Eric) CVE to CWE script handles if cwe is unknown so different node for other
						// unknown means we don't know the CWE for the CVE
						// other means it is a CWE outside of our software development view
						diag = diagnostics.get("CWE-other Trivy Diagnostic");
						LOGGER.warn("CVE with CWE outside of CWE-699 found.");
					}
					Finding finding = new Finding("",0,0,severityList.get(i));
					finding.setName(cveList.get(i));
					diag.setChild(finding);
				}


			} catch (JSONException e) {
				LOGGER.warn("Unable to read results form cve-bin-tool");
			}

			return diagnostics;
		}

		/**
		 * Initializes the tool by installing it through python pip from the command line.
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


		//maps low-critical to numeric values based on the highest value for each range.
		private Integer severityToInt(String severity) {
			Integer severityInt = 1;
			switch(severity.toLowerCase()) {
				case "low": {
					severityInt = 4;
					break;
				}
				case "medium": {
					severityInt = 7;
					break;
				}
				case "high": {
					severityInt = 9;
					break;
				}
				case "critical": {
					severityInt = 10;
					break;
				}
			}

			return severityInt;
		}

	/***
	 * simple utility to parse a file containing a one-liner NVD api key into class variable nvdApiKey
	 * @param path path where nvd api key exists, modified in config
	 * @return nvd api key
	 */
	private String parseKey(String path){
		//https://mkyong.com/java/java-convert-file-to-string/
		String content = "";
		try (Stream<String> lines = Files.lines(Paths.get(path))) {
			// Formatting like \r\n will be lost

			// UNIX \n, WIndows \r\n
			content = lines.collect(Collectors.joining(System.lineSeparator()));
			System.out.println(content);

		} catch (IOException e) {
			e.printStackTrace();
		}
		return content;
	}


}
