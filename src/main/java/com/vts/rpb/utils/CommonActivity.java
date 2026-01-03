package com.vts.rpb.utils;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class CommonActivity {
	
	public static String addingMonthValues(String month) 
	{
	    String[] months = { "04", "05", "06", "07", "08", "09", "10", "11", "12", "01", "02", "03"};
	    StringBuilder result = new StringBuilder();
	    for (String m : months) {
	        result.append(m);
	        if (m.equals(month)) break;
	        result.append(",");
	    }
	    return result.toString();
	}

	public static String[] getFundNextStatus(String fundStatus, Object rolesDetails, Object approvalsDetails)
	{
		String[] statusDetails = new String[6];
		String statusColor = "";
		String message = "NA";

		// 1. Handle Basic Fund Status Colors/Messages
		if (fundStatus != null) {
			if ("N".equalsIgnoreCase(fundStatus)) {
				statusColor = "#4b01a9";
				message = "Forward Pending";
			} else if ("R".equalsIgnoreCase(fundStatus)) {
				statusColor = "red";
				message = "Returned";
			} else if ("E".equalsIgnoreCase(fundStatus)) {
				statusColor = "#007e68";
				message = "Revoked";
			} else if ("A".equalsIgnoreCase(fundStatus)) {
				statusColor = "green";
				message = "Approved";
			}
		}

		String dhStatus = "NA", csStatus = "NA", ccStatus = "NA", scStatus = "NA", rcStatus = "NA";

		if (rolesDetails != null && approvalsDetails != null) {
			String rolesStr = rolesDetails.toString();
			String approvalsStr = approvalsDetails.toString();

			List<String> rolesList = Arrays.asList(rolesStr.split(","));
			String[] approvals = approvalsStr.split(",");

			// 2. Safe extraction helper (prevents IllegalArgumentException: -1)
			// Checks if role exists in list and index is within array bounds
			dhStatus = getSafeStatus(rolesList, approvals, "DH");
			csStatus = getSafeStatus(rolesList, approvals, "CS");
			ccStatus = getSafeStatus(rolesList, approvals, "CC");
			scStatus = getSafeStatus(rolesList, approvals, "SC");

			// 3. Handle RC (Member) logic
			Set<String> rcFilter = Set.of("CM", "SE");
			List<String[]> filtered = IntStream.range(0, Math.min(rolesList.size(), approvals.length))
					.filter(i -> rcFilter.contains(rolesList.get(i).trim()))
					.mapToObj(i -> new String[]{rolesList.get(i), approvals[i]})
					.collect(Collectors.toList());

			rcStatus = filtered.stream().map(a -> a[1]).collect(Collectors.joining(","));

			// 4. Update Message based on hierarchy
			if ("F".equalsIgnoreCase(fundStatus) || "B".equalsIgnoreCase(fundStatus)) {
				if ("N".equalsIgnoreCase(dhStatus)) {
					message = "DH Rec. Pending";
					statusColor = "#03458c";
				} else if (rcStatus.contains("N")) {
					message = "Member Rec. Pending";
					statusColor = "#9b0186";
				} else if ("N".equalsIgnoreCase(csStatus)) {
					message = "Review Pending";
					statusColor = "#8c2303";
				} else if ("N".equalsIgnoreCase(ccStatus) || "N".equalsIgnoreCase(scStatus)) {
					message = "Approval Pending";
					statusColor = "#bd0707";
				}
			}
		}

		statusDetails[0] = dhStatus;
		statusDetails[1] = rcStatus;
		statusDetails[2] = csStatus;
		statusDetails[3] = ccStatus;
		statusDetails[4] = message;
		statusDetails[5] = statusColor;

		return statusDetails;
	}

	/**
	 * Helper method to safely retrieve approval status by role name.
	 */
	private static String getSafeStatus(List<String> roles, String[] approvals, String targetRole) {
		int index = roles.indexOf(targetRole);
		if (index >= 0 && index < approvals.length) {
			return approvals[index];
		}
		return "NA"; // Return NA if role is not found
	}

public String safeSpecialCharcaterReplace (Object text)
{
	if(text == null)
	{
		return null;
	}

	return (text.toString().trim()).replace("'", "\\'").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ");
}

}
