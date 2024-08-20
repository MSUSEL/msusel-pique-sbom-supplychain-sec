package web;

import javax.xml.stream.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class CweDescriptionParser {
    public Map<String, String> buildCweDescriptions(String cweDescriptionXmlPath) {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        Map<String, String> weaknessDescriptions = new HashMap<>();
        String WEAKNESS_TAG = "Weakness";
        String DESCRIPTION_TAG = "Description";
        String weaknessId = "";
        String description = "";
        String tagName;

        try {
            XMLStreamReader reader = factory.createXMLStreamReader(Files.newInputStream(Paths.get(cweDescriptionXmlPath)));
            while(reader.hasNext()) {
                int event = reader.next();
                switch (event) {
                    case XMLStreamConstants.START_ELEMENT:
                        tagName = reader.getLocalName();
                        if (WEAKNESS_TAG.equals(tagName)) {
                            weaknessId = reader.getAttributeValue(null, "ID");
                        } else if (DESCRIPTION_TAG.equals(tagName)) {
                            description = reader.getAttributeValue(null, DESCRIPTION_TAG);
                        }
                        break;
                    case XMLStreamConstants.END_ELEMENT:
                        tagName = reader.getLocalName();
                        if (WEAKNESS_TAG.equals(tagName)) {
                            weaknessId = "";
                            description = "";
                        }
                        break;
                }
                if(!weaknessId.isEmpty() && !description.isEmpty()) {
                    weaknessDescriptions.put("id", weaknessId);
                    weaknessDescriptions.put("description", description);
                }
            }
            reader.close();
        } catch (FactoryConfigurationError | XMLStreamException | IOException e) {
            throw new RuntimeException(e);
        }

        return weaknessDescriptions;
    }
}
