package runnable;

import pique.utility.PiqueProperties;
import utilities.helperFunctions;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.Namespace;

public class Wrapper {

    public static void main(String[] args) {
        try {
            boolean helpFlag = check_help(args);
            ArgumentParser parser = ArgumentParsers.newFor("Wrapper").build()
                    .defaultHelp(true).defaultHelp(true).description("Entry point for PIQUE-SBOM-SUPPLYCHAIN-SEC");
            parser.addArgument("--runType")
                    .setDefault("evaluate")
                    .choices("derive", "evaluate")
                    .help("derive: derives a new quality model from the benchmark repository, using --file throws an IllegalArgumentException and prints the stack trace" +
                            "\n evaluate: evaluates SBOM with derived quality model, --file must used otherwise throws an IllegalArgumentException and prints the stack trace");
            parser.addArgument( "--file")
                    .dest("fileName")
                    .type(String.class)
                    .help("path to SBOM for evaluation (required if runType is evaluate)");
            parser.addArgument("--version")
                    .action(Arguments.storeTrue())
                    .setDefault(false)
                    .help("print version information and terminate program");
            parser.addArgument("--downloadNVD")
                    .action(Arguments.storeTrue())
                    .setDefault(false)
                    .help("Download the latest version of the NVD database");

            Namespace namespace = null;
            if (helpFlag) {
                System.out.println(parser.formatHelp());
                System.exit(0);
            } else {
                namespace = parser.parseArgs(args);
            }

            String runType = namespace.getString("runType");
            String fileName = namespace.getString("fileName");
            boolean printVersion = namespace.getBoolean("version");
            boolean downloadNVDFlag = namespace.getBoolean("downloadNVD");
            Properties prop = PiqueProperties.getProperties();

            if (printVersion) {
                Path version = Paths.get(prop.getProperty("version"));
                System.out.println("PIQUE-SBOM-SUPPLYCHAIN-SEC version " + version);
                System.exit(0);
            }
            if (downloadNVDFlag) {
                System.out.println("Starting NVD download");
                helperFunctions.downloadNVD();
                System.exit(0);
            }

            String nvdDictionaryPath = Paths.get(prop.getProperty("nvd-dictionary.location")).toString();
            File f = new File(nvdDictionaryPath);
            if (!f.isFile()) {
                System.out.println("Error: the National Vulnerability Database must be downloaded before deriving or evaluating. Use --help for more information.");
                System.exit(1);
            }

            if ("derive".equals(runType)) {
                if (fileName != null) {
                    throw new IllegalArgumentException("Incorrect input parameters given. Use --help for more information");
                }
                else {
                    // kick off deriver
                    new QualityModelDeriver();
                }
            }
            else if ("evaluate".equals(runType)) {
                if (fileName == null) {
                    new SingleProjectEvaluator();
                }
                else {
                    // kick off evaluator
                    new SingleProjectEvaluator(fileName);
                }
            }
            else {
                throw new IllegalArgumentException("Incorrect input parameters given. Use --help for more information");
            }

        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static boolean check_help(String[] args) {
        // check if the help flag was used
        boolean help = false;
        for (String arg : args) {
            if (arg.equals("--help")) {
                return true;
            }
        }
        return false;
    }

}
