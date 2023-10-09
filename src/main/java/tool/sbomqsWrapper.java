package tool;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONArray;
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
 * getting a package count of an SBOM used for normalization
 * @author Eric O'Donoghue
 *
 */
public class sbomqsWrapper extends Tool implements ITool {
    private static final Logger LOGGER = LoggerFactory.getLogger(sbomqsWrapper.class);
    public sbomqsWrapper() {
        super("sbomqs", null);
    }

    // Methods
    /**
     * @param projectLocation The path to a binary file for the desired solution of project to
     *             analyze
     * @return The path to the analysis results file
     */
    @Override
    public Path analyze(Path projectLocation) {
        LOGGER.info("sbomqs analyzing "+ projectLocation.toString());

        // clear previous results

        File tempResults = new File(System.getProperty("user.dir") + "/out/sbomqs.txt");
        tempResults.delete();
        tempResults.getParentFile().mkdirs();

        Properties prop = PiqueProperties.getProperties();
        String pathTosbomqs = prop.getProperty("sbomqs.location");

        String[] cmd = {pathTosbomqs,
                "score",
                "--json",
                projectLocation.toAbsolutePath().toString()};
        LOGGER.info(Arrays.toString(cmd));
        try {
            String results = helperFunctions.getOutputFromProgram(cmd,LOGGER);
            int indexOfFirstOpenBrace = results.indexOf('{');
            String r = indexOfFirstOpenBrace != -1 ? results.substring(indexOfFirstOpenBrace) : results;
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
     * parses output of tool from analyze().
     *
     * @param toolResults location of the results, output by analyze()
     * @return A Map<String,Diagnostic> with findings from the tool attached. Returns null if tool failed to run.
     */
    @Override
    public Map<String, Diagnostic> parseAnalysis(Path toolResults) {
        return new HashMap<>();
    }

    /**
     * Initializes the tool by installing it through python pip from the command line.
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
