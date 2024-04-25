package data.handlers;

import data.ghsaData.CweNode;
import data.ghsaData.Cwes;
import data.ghsaData.SecurityAdvisory;
import data.interfaces.JsonMarshaler;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

public class SecurityAdvisoryMarshaler implements JsonMarshaler<SecurityAdvisory> {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAdvisoryMarshaler.class);

    @Override
    public SecurityAdvisory unmarshalJson(String json) {
        SecurityAdvisory securityAdvisory = new SecurityAdvisory();
        Cwes cwes = new Cwes();
        try {
            JSONObject jsonObject = new JSONObject(json);
            JSONObject jsonResponse = jsonObject.optJSONObject("data").optJSONObject("securityAdvisory");
            if (jsonResponse != null) {
                securityAdvisory.setGhsaId(jsonResponse.optString("ghsaId"));
                securityAdvisory.setSummary(jsonResponse.optString("summary"));
                cwes.setNodes(getNodesFromJson(jsonResponse));
                securityAdvisory.setCwes(cwes);
            } else {
                LOGGER.info("GHSA response was null");
            }
        } catch (JSONException e) {
            LOGGER.error("Malformed Json", e);
            throw new RuntimeException(e);
        }

        return securityAdvisory;
    }

    @Override
    public String marshalJson(SecurityAdvisory obj) {
        return "";
    }

    private ArrayList<CweNode> getNodesFromJson(JSONObject response) {
        ArrayList<CweNode> nodes = new ArrayList<>();
        try {
            JSONArray jsonNodes = response.optJSONObject("cwes").optJSONArray("nodes");
            for(int i = 0; i < jsonNodes.length(); i++) {
                CweNode cweNode = new CweNode();
                cweNode.setCweId(jsonNodes.optJSONObject(i).getString("cweId"));
                nodes.add(cweNode);
            }
        } catch (JSONException e) {
            LOGGER.error("Malformed Json", e);
            throw new RuntimeException(e);
        }
        return nodes;
    }
}
