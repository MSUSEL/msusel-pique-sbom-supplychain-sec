package data.dao;

import java.util.List;
import java.util.Optional;

/**
 * Adapted from https://www.baeldung.com/java-dao-pattern
 * @param <T>
 */
public interface IDao<T> {
    Optional<T> getById(String id);
    List<T> getAll();
    void insert(T t);
    void update(T t);
    void delete(T t);
}
