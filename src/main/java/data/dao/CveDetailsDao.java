package data.dao;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import data.MongoConnection;
import data.cveData.CveDetails;
import data.handlers.CveDetailsMarshaller;
import data.interfaces.IJsonMarshaller;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.utility.PiqueProperties;

import java.util.Properties;


public class CveDetailsDao implements IDao<CveDetails> {

    private final MongoClient client = MongoConnection.getInstance();
    private final MongoDatabase db = client.getDatabase("nvdMirror");
    private final MongoCollection<Document> vulnerabilities = db.getCollection("vulnerabilities");
    private final IJsonMarshaller<CveDetails> cveDetailsMarshaller = new CveDetailsMarshaller();
    private static final Logger LOGGER = LoggerFactory.getLogger(CveDetailsDao.class);

    @Override
    public CveDetails getById(String id) {
        CveDetails cve = new CveDetails();
        Document retrievedDoc = vulnerabilities.find(Filters.eq("id", id)).first();
        if (retrievedDoc != null) {
            cve = cveDetailsMarshaller.unmarshallJson(retrievedDoc.toJson());
        } else {
            LOGGER.info("Requested data is not in the collection");
        }

        return cve;
    }

    @Override
    public void insert(CveDetails cve) {
        String cveDetails = cveDetailsMarshaller.marshallJson(cve);
        Document filter = new Document("id", cve.getId());
        long documentCount = vulnerabilities.countDocuments(filter);
        System.out.println(documentCount);

        if (documentCount == 0) {
            vulnerabilities.insertOne(Document.parse(cveDetails));
        } else {
            // TODO apply update operation? or error out?
            LOGGER.info("Document already exists");
            System.out.println("Document already exists");
        }
    }

    @Override
    public void update(CveDetails cveDetails) {

    }

    @Override
    public void delete(CveDetails cveDetails) {

    }
}
