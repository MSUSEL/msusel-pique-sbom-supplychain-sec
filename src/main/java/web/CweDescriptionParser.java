package web;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.io.FileUtils;

import javax.xml.stream.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class CweDescriptionParser {
    private final XMLInputFactory factory = XMLInputFactory.newInstance();

    public Map<String, String> buildCweDescriptionsMap(String cweDescriptionXmlPath) {
        String tagName;
        String WEAKNESS_TAG = "Weakness";
        String DESCRIPTION_TAG = "Description";
        Queue<String> tokenQueue = new LinkedList<>();
        Map<String, String> weaknessDescriptions = new HashMap<>();

        try {
            XMLStreamReader reader = factory.createXMLStreamReader(Files.newInputStream(Paths.get(cweDescriptionXmlPath)));
            while(reader.hasNext()) {
                if (reader.next() == XMLStreamConstants.START_ELEMENT) {
                    tagName = reader.getLocalName();
                    if (tagName.equals(WEAKNESS_TAG)) {
                        tokenQueue.add("CWE-" + reader.getAttributeValue(null, "ID"));
                    } else if (tagName.equals(DESCRIPTION_TAG) && !tokenQueue.isEmpty()) {
                        tokenQueue.add(reader.getElementText());
                        weaknessDescriptions.put(tokenQueue.remove(), tokenQueue.remove());
                    }
                }
            }
            reader.close();
        } catch (FactoryConfigurationError | XMLStreamException | IOException e) {
            throw new RuntimeException(e);
        }

        return weaknessDescriptions;
    }

    public void dumpWeaknessDescriptionsToFile(String cweDescriptionXmlPath) {
        try (FileWriter writer = new FileWriter("./out/CweDescriptions.json")) {
            writer.write(new Gson().toJson(buildCweDescriptionsMap(cweDescriptionXmlPath)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Map<String, String> buildWeaknessDescriptionMapFromFile(String jsonCweDescriptionsPath) {
        try {
            return new Gson().fromJson(FileUtils.readFileToString(new File(jsonCweDescriptionsPath), "UTF-8"),
                    new TypeToken<Map<String, String>>(){}.getType());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
