/*
 * MIT License
 *
 * Copyright (c) 2023 Montana State University Software Engineering Labs
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
import java.util.*;

import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import presentation.PiqueData;
import toolOutputObjects.RelevantVulnerabilityData;
import utilities.helperFunctions;
import pique.utility.PiqueProperties;

/**
 * Wraps the functionality of the CVE-bin-tool to analyze software bill of materials (SBOMs) for known vulnerabilities.
 * This class handles command-line execution of CVE-bin-tool, result parsing, and diagnostic reporting within the PIQUE framework.
 *
 * @author Eric O'Donoghue
 */
public class CveBinToolWrapper extends Tool implements ITool {
    private final PiqueData piqueData;
    private final String toolName = " CVE-bin-tool Diagnostic";
    private final String propertiesPath;
    private static final Logger LOGGER = LoggerFactory.getLogger(TrivyWrapper.class);

    public CveBinToolWrapper(PiqueData piqueData) {
        super("cve_bin_tool", null);
        this.piqueData = piqueData;
        this.propertiesPath = "src/main/resources/pique-properties.properties";
    }
    public CveBinToolWrapper(PiqueData piqueData, String propertiesPath) {
        super("cve_bin_tool", null);
        this.piqueData = piqueData;
        this.propertiesPath = propertiesPath;
    }

    /**
     * Executes the CVE-bin-tool via the command line to analyze vulnerabilities in the given SBOM file.
     * Results are stored in a JSON file in the output directory specified in the system properties.
     *
     * @param projectLocation The file path of the SBOM to analyze.
     * @return Path to the file containing the analysis results.
     * @throws IOException if there is an error executing the tool or handling the file operations.
     */
    @Override
    public Path analyze(Path projectLocation) {
        LOGGER.info(this.getName() + "  Analyzing "+ projectLocation.toString());

        // clear previous results
        File tempResults = new File(System.getProperty("user.dir") + "/out/cve_bin_tool.json");
        tempResults.delete();
        tempResults.getParentFile().mkdirs();

        // get NVD api key for cve-bin-tool
        Properties prop = null;
        try {
            prop = PiqueProperties.getProperties(propertiesPath);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String nvdApiKeyPath = prop.getProperty("nvd-api-key-path");

        String detectedFormat = detectFormat(projectLocation.toAbsolutePath());

        String spec = "";
        if (detectedFormat.equals("spdx")) {
            spec = "spdx.json";
        }
        // command for running cve-bin-tool on the command line
        // cve-bin-tool --disable-version-check --nvd-api-key {nvdApiKeyPath} --sbom {spec} -f json --output {output_path} --sbom-file {sbom_path}

        String[] cmd = {"cve-bin-tool",
                "--disable-version-check",
                "--nvd-api-key", nvdApiKeyPath,
                "--sbom", spec, // currently only scanning  cyclonedx SBOMs
                "-f", "json",
                //"--quiet",
                "-u", "daily", // update the NVD database daily
                "--output", tempResults.toPath().toAbsolutePath().toString(), // output path
                "--sbom-file", projectLocation.toAbsolutePath().toString()}; // product under analysis path
        LOGGER.info(Arrays.toString(cmd));

        // runs the command built above and captures the output, CVE-bin-tool itself will handle the file saving
        try {
            helperFunctions.getOutputFromProgram(cmd,LOGGER);
        } catch (IOException e) {
            LOGGER.error("Failed to run CVE-bin-tool");
            LOGGER.error(e.toString());
            e.printStackTrace();
        }

        return tempResults.toPath();
    }

    /**
     * Parses the JSON output from the CVE-bin-tool and converts it into a map of diagnostic information suitable for further analysis.
     * This method reads the tool output, processes the vulnerabilities found, and associates them with diagnostics defined in PIQUE.
     *
     * @param toolResults The file path containing the results of the CVE-bin-tool analysis.
     * @return A map containing the diagnostic results, or null if an error occurs during parsing or if the tool fails to run.
     */
    @Override
    public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
        IOutputProcessor<RelevantVulnerabilityData> outputProcessor = new ToolOutputProcessor(new VulnerabilityService(piqueData, toolName));
        String results = "";

        System.out.println(this.getName() + " Parsing Analysis...");
        LOGGER.debug(this.getName() + " Parsing Analysis...");

        // find all diagnostic nodes associated with CVE-bin-tool
        Map<String, Diagnostic> diagnostics = null;
        try {
            diagnostics = helperFunctions.initializeDiagnostics(this.getName(), propertiesPath);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Read and process cve-bin-tool output
        try {
            results = helperFunctions.readFileContent(toolResults);
        } catch (IOException e) {
            LOGGER.info("No results to read from CVE-bin-tool.");
        }

        JSONArray vulnerabilities = outputProcessor.getVulnerabilitiesFromToolOutput(results);
        if (vulnerabilities != null) {
            List<RelevantVulnerabilityData> cveBinToolVulnerabilities = outputProcessor.processToolVulnerabilities(vulnerabilities);
            outputProcessor.addDiagnostics(cveBinToolVulnerabilities, diagnostics);
        } else {
            LOGGER.warn("Vulnerability array was empty.");
        }

        return diagnostics;
    }

    /**
     * Prints the version of CVE-bin-tool via a command line call. This method is a placeholder due to dockerization,
     * which handles the actual installation and setup of the tool. Must remain implemented to fulfill interface obligations.
     *
     * @param toolRoot The root directory for the tool, not utilized in the current dockerized setup.
     * @return The same toolRoot path passed as an argument.
     */
    @Override
    public Path initialize(Path toolRoot) {
        final String[] cmd = {"cve-bin-tool", "--version"};

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
     * Inspects the SBOM file at the given path and returns the detected format.
     * It returns "spdx" if an SPDX signature is found, "cyclonedx" if a CycloneDX signature is found,
     * or a default (for example, "spdx") if no clear signature is identified.
     *
     * @param sbomPath the path to the SBOM file
     * @return a string indicating the format ("spdx" or "cyclonedx")
     */
    private String detectFormat(Path sbomPath) {
        try {
            // Read the first 1000 bytes (or a set number of lines) to get a good sample of the content
            List<String> lines = Files.readAllLines(sbomPath);
            for (String line : lines) {
                // Check for SPDX signature
                if (line.contains("SPDXVersion:")) {
                    return "spdx";
                }
                // Check for CycloneDX signature (if the SBOM is JSON, for instance)
                if (line.contains("\"bomFormat\"") && line.contains("CycloneDX")) {
                    return "cyclonedx";
                }
                // Optionally, check for an XML signature if you expect CycloneDX in XML format:
                if (line.contains("<bom") && line.contains("CycloneDX")) {
                    return "cyclonedx";
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        // Fallback decision: you might choose to default to SPDX if no signature is found
        return "spdx";
    }
}
