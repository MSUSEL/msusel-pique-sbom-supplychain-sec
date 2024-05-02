package data;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;

public class MongoConnection {
   private static MongoClient mongoClient = null;

    private MongoConnection() {}

    public static MongoClient getInstance() {
        if (mongoClient == null) {
            synchronized (MongoClient.class) {
                if (mongoClient == null) {
                    mongoClient = MongoClients.create("mongodb://localhost:27017");
                }
            }
        }
        return mongoClient;
    }
}
