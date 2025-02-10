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
package toolTests;

import evaluator.ProbabilityDensityFunctionUtilityFunctionExperimental;
import org.junit.Ignore;
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


    @Test @Ignore
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
