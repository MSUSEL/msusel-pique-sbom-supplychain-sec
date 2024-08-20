package web;

import com.google.gson.Gson;
import org.bson.json.JsonObject;

import javax.xml.stream.*;
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
                        tokenQueue.add(reader.getAttributeValue(null, "ID"));
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
        Gson gson = new Gson();
        Map<String, String> cweDescriptions = buildCweDescriptionsMap(cweDescriptionXmlPath);
        String jsonCweDescription = gson.toJson(cweDescriptions);

        try (FileWriter writer = new FileWriter("./out/CweDescriptions")) {
            writer.write(jsonCweDescription);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
