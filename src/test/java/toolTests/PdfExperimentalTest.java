package toolTests;

import evaluator.ProbabilityDensityFunctionUtilityFunctionExperimental;
import org.junit.Test;
import pique.analysis.Tool;
import pique.model.Diagnostic;
import pique.utility.PiqueProperties;
import presentation.PiqueData;
import presentation.PiqueDataFactory;
import runnable.QualityModelDeriver;
import runnable.SingleProjectEvaluator;
import tool.TrivyWrapper;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PdfExperimentalTest {


    @Test
    public void testPdfVaryingHyperParameters() {
        Properties prop = PiqueProperties.getProperties();

        String[] kernelFunctions = {"GAUSSIAN"};
        double[] bandwidths = {0.1, 0.5, 1, 1.5, 2, 100};
        int[] samplingSpaces = {10, 100, 1000, 10000};

        int expCount = kernelFunctions.length * bandwidths.length * samplingSpaces.length;
        System.out.println("Running " + expCount + " experiments");

        for (String kernelFunction : kernelFunctions) {
            for (double bandwidth : bandwidths) {
                for (int samplingSpace : samplingSpaces) {
                    System.out.println("Running experiment with kernel function: " + kernelFunction + ", bandwidth: " + bandwidth + ", sampling space: " + samplingSpace);
                    //QualityModelDeriver deriver = new QualityModelDeriver();

                    // TODO figure out how to save each result with a unique name based on the hyperparameters

                    ProbabilityDensityFunctionUtilityFunctionExperimental.currentBandwidth = bandwidth;
                    ProbabilityDensityFunctionUtilityFunctionExperimental.currentSamplingSpace = samplingSpace;

                    String sbomInputPath = prop.getProperty("project.sbom-input");
                    String sourceCodeInputPath = prop.getProperty("project.source-code-input");

                    String parameters = "kf:" + kernelFunction + "--b:" + bandwidth + "--samplingSpace:" + samplingSpace;
                    SingleProjectEvaluator evaluator = new SingleProjectEvaluator(sbomInputPath, sourceCodeInputPath, "syft-fs", parameters);
                }
            }
        }
    }
}
