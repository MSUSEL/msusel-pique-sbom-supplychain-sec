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

import java.nio.file.Path;

/**
 * Interface definition for SBOM generation tools
 */
public interface IGenerationTool {
    /**
     * Generates an SBOM for a given project location using Trivy. The SBOM is created in the CycloneDX format
     * and saved to a predetermined directory under the project's root directory.
     * This method constructs the command to run Syft with the necessary arguments to produce the SBOM,
     * executes the command, and logs the process and potential errors.
     *
     * @param projectLocation The file path of the project directory for which to generate the SBOM.
     */
    void generateSource(Path projectLocation, Path sbomDirectory);
    void generateImage(Path projectLocation, Path sbomDirectory);
}
