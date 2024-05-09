package data.dao;

import data.cveData.CveDetails;

import java.util.List;
import java.util.Optional;

/**
 * Adapted from https://www.baeldung.com/java-dao-pattern
 * @param <T>
 */
public interface IDao<T> {
    T getById(String id);
    void insert(T t);
    void update(T t);
    void delete(T t);
}
