package data;

import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import pique.utility.PiqueProperties;

import java.util.Properties;

public class MongoCreds {
    private final Properties prop = PiqueProperties.getProperties();

    String username = "tempuser";
    String password = "mypass";
    String database = "mongodb";
    String hostname = "localhost";

    MongoCredential credential = MongoCredential.create(
            username, database, password.toCharArray(), new ServerAddress(hostname, ));
}
