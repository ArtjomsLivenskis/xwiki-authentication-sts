package com.xwiki.authentication.sts;

import java.util.ArrayList;
import java.util.List;

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
		String normalizedList = "";
		if (errorList.size() > 0) {
			normalizedList = "\n\n***** ERROR LIST *****\n";
			for (Throwable currentThrowable : errorList) {
				normalizedList = normalizedList + currentThrowable;
				if (currentThrowable.getCause() == null)
					normalizedList += "\n";
				else
					normalizedList = normalizedList
							+ currentThrowable.getCause()
							+ "\n";
			}
			normalizedList = normalizedList + "**********************"
					+ "\n";
		}
		return normalizedList;
	}

	public void clearErrorList() {
		errorList.clear();
	}

	public int geterrorListLength() {
		return errorList.size();
	}
}
