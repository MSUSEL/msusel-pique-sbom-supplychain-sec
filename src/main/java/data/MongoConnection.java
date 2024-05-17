package data;

import com.mongodb.MongoClientException;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import pique.utility.PiqueProperties;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

public class MongoConnection {
    private static MongoClient mongoClient = null;

    private MongoConnection() {}
    public static MongoClient getInstance() {
        List<List<String>> credentials;
        try {
            credentials = getMongoCredentials();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String username = credentials.get(0);

        if (mongoClient == null) {
            synchronized (MongoClient.class) {
                if (mongoClient == null) {
                    MongoCredential credential = MongoCredential.createCredential(username, authenticationDB, password.toCharArray());
                    try {
                        mongoClient = MongoClients.create(
                                MongoClientSettings.builder()
                                        .applyToClusterSettings(builder ->
                                                builder.hosts(Arrays.asList(new ServerAddress(hostname, Integer.parseInt(port)))))
                                        .credential(credential)
                                        .build());
                    } catch (MongoClientException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }

        return mongoClient;
    }

    public static List<String> getMongoCredentials() throws IOException {
        Properties prop = PiqueProperties.getProperties();
        List<String>creds;

        // reads credentials file and splits into 2-D ArrayList of credentials
        creds = Files.readAllLines(Paths.get(prop.getProperty("mongo-credentials-path")));
        //TODO still need to make this a map
        return creds;
    }
}
