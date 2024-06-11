package tool;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.analysis.ITool;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.utility.PiqueProperties;
import utilities.helperFunctions;

import java.io.*;
import java.nio.file.Path;
import java.util.*;


/**
 * CODE TAKEN FROM PIQUE-BIN-DOCKER AND MODIFIED FOR PIQUE-SBOM-SUPPLYCHAIN-SEC.
 *
 * This tool wrapper will run and analyze the output of the tool sbomqs. This is used for
 * getting a package count of an SBOM used for normalization.
 * @author Eric O'Donoghue
 *
 */
public class sbomqsWrapper extends Tool implements ITool {
    private static final Logger LOGGER = LoggerFactory.getLogger(sbomqsWrapper.class);

    public sbomqsWrapper() {
        super("sbomqs", null);
    }

    /**
     * Rums sbomqs through the command line on the given SBOM and saves the results to a temporary file.
     *
     * @param projectLocation The path to an SBOM file for the desired solution of project to analyze
     * @return The path to the analysis results file
     */
    @Override
    public Path analyze(Path projectLocation) {
        LOGGER.info("sbomqs analyzing "+ projectLocation.toString());

        // clear previous results
        File tempResults = new File(System.getProperty("user.dir") + "/out/sbomqs.txt");
        tempResults.delete();
        tempResults.getParentFile().mkdirs();

        // get location of sbomqs executable
        Properties prop = PiqueProperties.getProperties();
        File sbomqsPath = new File(System.getProperty("user.dir") + "/" + prop.getProperty("sbomqs.location"));

        // command for running sbomqs on the command line
        String[] cmd = {"sbomqs", //sbomqsPath.toPath().toAbsolutePath().toString(),
                "score",
                "--json",
                projectLocation.toAbsolutePath().toString()};
        LOGGER.info(Arrays.toString(cmd));

        // runs the command built above and captures the output
        // sbomqs does not handle file saving, so we must parse the captured output and save it to a text file
        try {
            // parse results captured from standard out
            String results = helperFunctions.getOutputFromProgram(cmd,LOGGER);
            int indexOfFirstOpenBrace = results.indexOf('{');
            String r = indexOfFirstOpenBrace != -1 ? results.substring(indexOfFirstOpenBrace) : results;

            // we only want to save the component count, parse the output saved as a json for the num_components field
            JSONObject jsonResults = new JSONObject(r);
            int componentCount = jsonResults.getJSONArray("files").getJSONObject(0).getInt("num_components");

            FileWriter fileWriter = new FileWriter(tempResults);
            fileWriter.write(Integer.toString(componentCount));
            fileWriter.close();
        } catch (IOException  e) {
            LOGGER.error("Failed to run or save sbomqs");
            LOGGER.error(e.toString());
            e.printStackTrace();
        } catch (JSONException e) {
            LOGGER.error("Failed to save sbomqs results");
            LOGGER.error(e.toString());
            e.printStackTrace();
        }
        return tempResults.toPath();
    }

    /**
     * We are using this tool to only capture package count for normalization so we do not need to
     * parse the analysis. This function must be overridden so we return an empty map.
     *
     * @param toolResults location of the results, output by analyze()
     * @return An empty Map<String,Diagnostic>
     */
    @Override
    public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
        return new HashMap<>();
    }

    /**
     * Initializes the tool by installing it through python pip from the command line.
     *
     * Because of dockerization this is no longer needed and currently just prints the version.
     * Method must be left because it must be overridden.
     */
    @Override
    public Path initialize(Path toolRoot) {
        final String[] cmd = {"sbomqs", "version"};

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
