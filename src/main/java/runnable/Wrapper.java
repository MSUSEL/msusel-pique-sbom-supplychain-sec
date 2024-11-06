package runnable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.utility.PiqueProperties;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.Namespace;

/**
 * Main entry point for the PIQUE-SBOM-SUPPLYCHAIN-SEC application. This class handles the
 * initial command-line interface setup for the application, processing input arguments to
 * determine the operational mode (either deriving a new quality model or evaluating SBOMs),
 * and initiating the appropriate processes based on the user's choice.
 *
 * @author Eric O'Donoguhe
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
            parser.addArgument("--gen_tool")
                    .setDefault("none")
                    .choices("syft-fs", "trivy-fs", "syft-image", "trivy-image", "cdxgen")
                    .help("specify the tool to use for SBOM generation");

            if (helpFlag) {
                System.out.println(parser.formatHelp());
                System.exit(0);
            } else {
                namespace = parser.parseArgs(args);
            }

            String runType = namespace.getString("runType");
            String genTool = namespace.getString("gen_tool");
            boolean printVersion = namespace.getBoolean("version");

            if (printVersion) {
                Path version = Paths.get(prop.getProperty("version"));
                System.out.println("PIQUE-SBOM-SUPPLYCHAIN-SEC version " + version);
                System.exit(0);
            }

            if ("derive".equals(runType)) {
                // kick off deriver
                new QualityModelDeriver();
            }
            else if ("evaluate".equals(runType)) {
                // kick off evaluator
                // get path to input projects
                String sbomInputPath = prop.getProperty("project.sbom-input");
                String sourceCodeInputPath = prop.getProperty("project.source-code-input");
                new SingleProjectEvaluator(sbomInputPath, sourceCodeInputPath, genTool);
                System.exit(0);
            }
            else {
                LOGGER.error("Illegal Argument Exception: incorrect input parameter given. Use --help for more information.");
                throw new IllegalArgumentException("Incorrect input parameters given. Use --help for more information");
            }
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
