package runnable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.utility.PiqueProperties;
import tool.GrypeWrapper;
import utilities.helperFunctions;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.Namespace;

import static java.lang.Thread.sleep;

/**
 * Entry point for the model. Handles 3 distinct operations:
 * * Downloading the national vulnerability database utilizing the NVDs 2.0 API, see
 *   download_nvd.py for more details.
 * * Kicking off the derive stage of the PIQUE process, runs QualityModelDeriver.java, generating a
 *   quality model from the benchmark repository found in resources (saved to out/SBOMSupplyChainSecurityQualityModelCWE-699.json).
 * * Kicking off the evaluation stage of the PIQUE process, runs SingleProjectEvaluator, builds
 *   quality models for the SBOMs in input/projects using the derived model. Results are saved to out.
 *
 * @author Eric O'Donoghue
 */
public class Wrapper {
    private static final Logger LOGGER = LoggerFactory.getLogger(Wrapper.class);

    public static void main(String[] args) {
        Properties prop = PiqueProperties.getProperties();
        Namespace namespace = null;
        try {
            // setup command line argument parsing
            boolean helpFlag = check_help(args);
            ArgumentParser parser = ArgumentParsers.newFor("Wrapper").build()
                    .defaultHelp(true)
                    .defaultHelp(true)
                    .description("Entry point for PIQUE-SBOM-SUPPLYCHAIN-SEC");
            
            parser.addArgument("--runType")
                    .setDefault("evaluate")
                    .choices("derive", "evaluate")
                    .help("derive: derives a new quality model from the benchmark repository" +
                            "\nevaluate: evaluates SBOMs located in input/projects with derived quality model");

            parser.addArgument("--version")
                    .action(Arguments.storeTrue())
                    .setDefault(false)
                    .help("print version information and terminate program");
//            parser.addArgument("--downloadNVD")
//                    .action(Arguments.storeTrue())
//                    .setDefault(false)
//                    .help("Download the latest version of the NVD database then terminate program");

            if (helpFlag) {
                System.out.println(parser.formatHelp());
                System.exit(0);
            } else {
                namespace = parser.parseArgs(args);
            }

            String runType = namespace.getString("runType");
            boolean printVersion = namespace.getBoolean("version");
            //boolean downloadNVDFlag = namespace.getBoolean("downloadNVD");

            if (printVersion) {
                Path version = Paths.get(prop.getProperty("version"));
                System.out.println("PIQUE-SBOM-SUPPLYCHAIN-SEC version " + version);
                System.exit(0);
            }
//            if (downloadNVDFlag) {
//                System.out.println("Starting NVD download");
//                LOGGER.info("Wrapper: Starting NVD download");
//                helperFunctions.downloadNVD();
//                System.exit(0);
//            }

//            String nvdDictionaryPath = Paths.get(prop.getProperty("nvd-dictionary.location")).toString();
//            File f = new File(nvdDictionaryPath);
//            if (!f.isFile()) {
//                System.out.println("NVD database not yet downloaded - starting NVD download");
//                LOGGER.info("Wrapper: NVD database not yet downloaded - starting NVD download");
//                helperFunctions.downloadNVD();
//                System.out.println("finish NVD download");
//                LOGGER.info("Wrapper: finished NVD download");
//            }
//
//            // kick off query_nvd.py on its own thread
//            String pathToNVDDict = prop.getProperty("nvd-dictionary.location");
//            String pathToScript = prop.getProperty("query-nvd.location");
//            String port_number = prop.getProperty("query-nvd.port");
//            String[] cmd = {"python3", pathToScript, pathToNVDDict, port_number};
//            Thread query_nvd = new Thread(() -> {
//                try {
//                    helperFunctions.getOutputFromProgram(cmd, LOGGER);
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
//            });
//            System.out.println("Starting server for converting vulnerabilities to CWEs");
//            LOGGER.info("Wrapper: Starting query_nvd.py");
//            query_nvd.start();
//
//            // todo implement functionality for responding when dict is loaded instead of sleeping
//            sleep(12000);

            if ("derive".equals(runType)) {
                // kick off deriver
                new QualityModelDeriver();
            }
            else if ("evaluate".equals(runType)) {
                // kick off evaluator
                // get path to input projects
                String input_path = prop.getProperty("project.root");
                new SingleProjectEvaluator(input_path);
                System.exit(0);
            }
            else {
                LOGGER.error("Illegal Argument Exception: incorrect input parameter given. Use --help for more information.");
                throw new IllegalArgumentException("Incorrect input parameters given. Use --help for more information");
            }
            //query_nvd.join();
        }
        catch (Exception e) {
            e.printStackTrace();
            LOGGER.error("Exception caught: " + e);
        }
    }

    private static boolean check_help(String[] args) {
        // check if the help flag was used
        for (String arg : args) {
            if (arg.equals("--help")) {
                return true;
            }
        }
        return false;
    }

}
