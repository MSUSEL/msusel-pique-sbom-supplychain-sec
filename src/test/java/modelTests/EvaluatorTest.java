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
package modelTests;

import org.junit.Test;
import pique.utility.PiqueProperties;
import runnable.QualityModelDeriver;
import runnable.SingleProjectEvaluator;

import java.io.IOException;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.fail;

public class EvaluatorTest {


    @Test
    public void SingleProjectEvaluatorTest() throws IOException {
        Properties prop = PiqueProperties.getProperties("/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/test/resources/pique-properties-TEST.properties");

        String sbomInputPath = prop.getProperty("project.sbom-input");

        try {
            SingleProjectEvaluator eval = new SingleProjectEvaluator(sbomInputPath, "", "", "/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/test/resources/pique-properties-TEST.properties");
        }
        catch (Exception e) {
            System.out.println("Error: " + e);
            e.printStackTrace();
            fail();
        }

    }

    @Test
    public void SingleProjectEvaluatorGenerateTrivyTest() throws IOException {
        Properties prop = PiqueProperties.getProperties("/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/test/resources/pique-properties-TEST.properties");

        String sbomInputPath = prop.getProperty("project.sbom-input");

        try {
            SingleProjectEvaluator eval = new SingleProjectEvaluator(sbomInputPath, "trivy", "", "/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/test/resources/pique-properties-TEST.properties");
        }
        catch (Exception e) {
            System.out.println("Error: " + e);
            e.printStackTrace();
            fail();
        }

    }

    @Test
    public void SingleProjectEvaluatorGenerateSyftTest() throws IOException {
        Properties prop = PiqueProperties.getProperties("/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/test/resources/pique-properties-TEST.properties");

        String sbomInputPath = prop.getProperty("project.sbom-input");

        try {
            SingleProjectEvaluator eval = new SingleProjectEvaluator(sbomInputPath, "syft", "", "/home/eric/Documents/research/PIQUE-SBOM-dev/current/msusel-pique-sbom-supplychain-sec/src/test/resources/pique-properties-TEST.properties");
        }
        catch (Exception e) {
            System.out.println("Error: " + e);
            e.printStackTrace();
            fail();
        }

    }
    
}
