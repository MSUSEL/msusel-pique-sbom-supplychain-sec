package data.dao;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.InsertOneModel;
import com.mongodb.client.model.ReplaceOptions;
import com.mongodb.client.model.WriteModel;
import com.mongodb.client.result.UpdateResult;
import data.MongoConnection;
import data.cveData.CVEResponse;
import data.cveData.CveDetails;
import data.handlers.NvdCveMarshaler;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class NvdMetaDataDao {
    private final MongoClient client = MongoConnection.getInstance();
    private final MongoDatabase db = client.getDatabase("nvdMirror");
    private final MongoCollection<Document> vulnerabilities = db.getCollection("vulnerabilities");
    private final NvdCveMarshaler nvdCveMarshaler = new NvdCveMarshaler();
    private static final Logger LOGGER = LoggerFactory.getLogger(NvdMetaDataDao.class);
    private final Document filter = new Document("_id", "nvd_metadata");

    public void insert(CVEResponse cveResponse) {
        Document metadata = generateMetadata(cveResponse);
        long documentCount = vulnerabilities.countDocuments(filter);
        if(documentCount == 0) {
            vulnerabilities.insertOne(metadata);
        }
    }

    public void replace(CVEResponse cveResponse) {
        Document metadata = generateMetadata(cveResponse);
        ReplaceOptions opts = new ReplaceOptions().upsert(true);
        UpdateResult updateResult = vulnerabilities.replaceOne(filter, metadata, opts);

        System.out.println("Modified document count: " + updateResult.getModifiedCount());
        System.out.println("Upserted id: " + updateResult.getUpsertedId());
    }

    public Document get(Document criteria) {
        return null;
    }

    private Document generateMetadata(CVEResponse cveResponse) {
        return new Document("_id", "nvd_metadata")
                .append("totalResults", cveResponse.getTotalResults())
                .append("format", cveResponse.getFormat())
                .append("version", cveResponse.getVersion())
                .append("timestamp", cveResponse.getTimestamp());
    }
}
