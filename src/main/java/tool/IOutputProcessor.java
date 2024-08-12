package tool;

import org.json.JSONArray;
import pique.model.Diagnostic;

import java.util.ArrayList;
import java.util.Map;

/**
 * This is probably overengineered but given the ongoing discussion about how to
 * make PIQUE more reusable and extensible, this interface demonstrates the ability
 * to decouple logic from implementation details.
 * @param <T> java class that contains the fields needed to build findings and diagnostics
 */
public interface IOutputProcessor<T> {
    JSONArray getVulnerabilitiesFromToolOutput(String results, String toolName);
    ArrayList<T> processToolVulnerabilities(JSONArray jsonVulns, String toolName);
    void addDiagnostics(ArrayList<T> toolVulnerabilities, Map<String, Diagnostic> diagnostics, String toolName);
}
