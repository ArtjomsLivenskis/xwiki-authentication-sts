package com.xwiki.authentication.sts;

import java.util.ArrayList;
import java.util.List;

import org.apache.tools.ant.types.resources.selectors.InstanceOf;

public class STSErrorCollector {

	private List<Throwable> errorList;

	public STSErrorCollector() {
		errorList = new ArrayList<Throwable>();
	}

	public void addError(Object obj) {
		if (obj instanceof Throwable)
			errorList.add((Throwable) obj);
	}

	public String listErrors() {
		String normalizedList = System.lineSeparator() + "================"
				+ System.lineSeparator() + "ERROR LIST"
				+ System.lineSeparator() + "================"
				+ System.lineSeparator();
		for (Throwable currentThrowable : errorList) {
			normalizedList = normalizedList + currentThrowable + ": "
					+ currentThrowable.getCause() + System.lineSeparator();
		}
		return normalizedList + "================" + System.lineSeparator();
	}
	
	public void clearErrorList(){
		errorList.clear();
	}
}
