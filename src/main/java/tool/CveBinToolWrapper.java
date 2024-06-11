package tool;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;

import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import toolOutputObjects.RelevantVulnerabilityData;
import utilities.helperFunctions;
import pique.utility.PiqueProperties;


public class CveBinToolWrapper extends Tool implements ITool {
    private static final Logger LOGGER = LoggerFactory.getLogger(TrivyWrapper.class);

    public CveBinToolWrapper() {
        super("cve_bin_tool", null);
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
        File tempResults = new File(System.getProperty("user.dir") + "/out/cve_bin_tool.json");
        tempResults.delete();
        tempResults.getParentFile().mkdirs();

        // get NVD api key for cve-bin-tool
        Properties prop = PiqueProperties.getProperties();
        String nvdApiKeyPath = prop.getProperty("nvd-api-key-path");
        String spec = "cyclonedx";
        // command for running cve-bin-tool on the command line
        // cve-bin-tool --disable-version-check --nvd-api-key {nvdApiKeyPath} --sbom {spec} -f json --output {output_path} --sbom-file {sbom_path}
        /** TODO: need to figure out a way to get the SBOM format that we are running this command it seems that
         *  CVE-bin-tool is not nearly as sophisticated as Trivy/Grype when determining SBOM format, it just defualts to SPDX
        */
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
     * Parses output of tool from analyze().
     *
     * @param toolResults location of the results, output by analyze()
     * @return A Map<String,Diagnostic> with findings from the tool attached. Returns null if tool failed to run.
     */
    @Override
    public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
        IOutputProcessor<RelevantVulnerabilityData> outputProcessor = new CveBinToolOutputProcessor();
        String results = "";
        String toolName = " CVE-bin-tool Diagnostic";

        System.out.println(this.getName() + " Parsing Analysis...");
        LOGGER.debug(this.getName() + " Parsing Analysis...");

        // find all diagnostic nodes associated with CVE-bin-tool
        Map<String, Diagnostic> diagnostics = helperFunctions.initializeDiagnostics(this.getName());

        // Read and process cve-bin-tool output
        try {
            results = helperFunctions.readFileContent(toolResults);
        } catch (IOException e) {
            LOGGER.info("No results to read from CVE-bin-tool.");
        }

        JSONArray vulnerabilities = outputProcessor.getVulnerabilitiesFromToolOutput(results, toolName);
        if (vulnerabilities != null) {
            ArrayList<RelevantVulnerabilityData> cveBinToolVulnerabilities = outputProcessor.processToolVulnerabilities(vulnerabilities, toolName);
            outputProcessor.addDiagnostics(cveBinToolVulnerabilities, diagnostics, toolName);
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
