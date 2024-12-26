package com.ILG.conversor_xml_api.Config;

import org.w3c.dom.Element; // Alterado para a classe correta
import java.util.Map;

public class XmlProcessingResult {
    private Element rootElement;
    private Map<String, String> columns;

    public XmlProcessingResult(Element rootElement, Map<String, String> columns) {
        this.rootElement = rootElement;
        this.columns = columns;
    }

    public Element getRootElement() {
        return rootElement;
    }

    public Map<String, String> getColumns() {
        return columns;
    }
}
