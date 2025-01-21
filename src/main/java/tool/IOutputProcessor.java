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

import org.json.JSONArray;
import pique.model.Diagnostic;

import java.util.List;
import java.util.Map;

/**
 * This is probably overengineered but given the ongoing discussion about how to
 * make PIQUE more reusable and extensible, this interface demonstrates the ability
 * to decouple logic from implementation details.
 * @param <T> java class that contains the fields needed to build findings and diagnostics
 */
public interface IOutputProcessor<T> {
    JSONArray getVulnerabilitiesFromToolOutput(String results);
    List<T> processToolVulnerabilities(JSONArray jsonVulns);
    void addDiagnostics(List<T> toolVulnerabilities, Map<String, Diagnostic> diagnostics);
}
