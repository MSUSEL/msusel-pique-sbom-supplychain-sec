/**
 * MIT License
 * Copyright (c) 2019 Montana State University Software Engineering Labs
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

import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.model.Diagnostic;
import pique.model.Finding;
import toolOutputObjects.RelevantVulnerabilityData;

import java.util.List;
import java.util.Map;

public class ToolOutputProcessor implements IOutputProcessor<RelevantVulnerabilityData> {
    private final VulnerabilityService vulnerabilityService;
    private static final Logger LOGGER = LoggerFactory.getLogger(ToolOutputProcessor.class);

    public ToolOutputProcessor(VulnerabilityService vulnerabilityService) {
        this.vulnerabilityService = vulnerabilityService;
    }

    /**
     * Gets the vulnerabilities array from the complete Tool results
     *
     * @param results tool output in String format
     * @return a jsonArray of Tool results or null if no vulnerabilities are found
     */
    @Override
    public JSONArray getVulnerabilitiesFromToolOutput(String results) {
        return vulnerabilityService.extractVulnerabilities(results);
    }

    /**
     * Processes the JSONArray of tool output vulnerabilities into java objects.
     * This makes it easier to store and process data into Findings later.
     * Once created, these objects are read-only.
     *
     * @param jsonVulns JSONArray of tool output vulnerabilities
     * @return ArrayList of RelevantVulnerabilityData java objects
     */
    @Override
    public List<RelevantVulnerabilityData> processToolVulnerabilities(JSONArray jsonVulns) {
        return vulnerabilityService.processVulnerabilities(jsonVulns);
    }

    /**
     * Builds Finding and Diagnostic objects from the list of ToolVulnerabilities generated previously.
     * Adds the new Diagnostics to the PIQUE tree.
     *
     * @param toolVulnerabilities ArrayList of RelevantVulnerabilityData objects representing Output from Tool
     * @param diagnostics Map of diagnostics for Tool output
     */
    @Override
    public void addDiagnostics(List<RelevantVulnerabilityData> toolVulnerabilities, Map<String, Diagnostic> diagnostics) {
        String toolName = vulnerabilityService.getToolName();

        for (RelevantVulnerabilityData relevantVulnerabilityData : toolVulnerabilities) {
            Diagnostic diag = diagnostics.get(relevantVulnerabilityData.getCwe().get(0) + toolName);
            if (diag == null) {
                diag = diagnostics.get("CWE-other" + toolName);
                LOGGER.warn("CVE with CWE outside of CWE-699 found.");
            }
            Finding finding = new Finding("", 0, 0, relevantVulnerabilityData.getSeverity());
            finding.setName(relevantVulnerabilityData.getCve());
            diag.setChild(finding);
        }
    }
}
