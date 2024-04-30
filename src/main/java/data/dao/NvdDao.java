package data.dao;

import data.cveData.CveDetails;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class NvdDao implements IDao<CveDetails> {
    @Override
    public Optional<CveDetails> getById(String id) {
        return Optional.empty();
    }

    @Override
    public List<CveDetails> getAll() {
        return Collections.emptyList();
    }

    @Override
    public void insert(CveDetails cveDetails) {

    }

    @Override
    public void update(CveDetails cveDetails) {

    }

    @Override
    public void delete(CveDetails cveDetails) {

    }
}
