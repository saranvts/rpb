<%@page import="com.vts.rpb.utils.CommonActivity"%>
<%@page import="java.util.stream.Collectors"%>
<%@page import="java.util.stream.IntStream"%>
<%@page import="com.vts.rpb.utils.AmountConversion"%>
<%@page import="java.math.BigDecimal"%>
<%@page import="com.vts.rpb.fundapproval.dto.FundApprovalBackButtonDto"%>
<%@page import="com.google.gson.Gson"%>
<%@page import="org.json.simple.JSONArray"%>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ page import="java.util.*,com.vts.*,java.text.SimpleDateFormat"%>
<%@page import="com.vts.rpb.utils.DateTimeFormatUtil" %>

<%@page import="java.text.DecimalFormat"%>
<%@ page import="java.util.List"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<jsp:include page="../static/header.jsp"></jsp:include>
<jsp:include page="../fundapproval/fundModal.jsp"></jsp:include>
<title>FUND APPROVAL LIST</title>

<style type="text/css">

.badge-counter
{
    margin-left: 0rem;
}

#fbePendingtab.nav-link.active {
    background-color: #cd8858 /* #cb7335 */ /* #cf4754 */ /* #813b3b */;
    font-weight: 600;
}
#fbeApprovedtab.nav-link.active {
    background-color: #066006;
    font-weight: 600; 
}

</style>
<style>

.greek-style {
            font-family: 'Times New Roman', Times, serif;
            font-weight: bold;
            font-style: italic;
            color: blue;
        }
        .recommendation-item {
            display: flex;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }

        .recommendation-item span {
            display: inline-block;
            margin-right: 10px;
        }

        .recommendation-value {
            font-weight: 600;
             color: #0303b9;
        }

        .recommendation-container {
            border: 0px solid #ccc;
            padding: 20px;
            border-radius: 5px;
        }

        .recommendation-item b {
            min-width: 150px;
            display: inline-block;
        }
    </style>
    
    <!-- Tab Styles -->
    <style>
    
    .tabs-container {
      max-width: 99% !important;
      margin: 0 auto;
    }
    /* hide native radio buttons */
    .tabs-container > input[type="radio"] {
      position: absolute;
      left: -100vw;
    }
    /* labels styled as tabs */
    .tabs-container > label {
      display: inline-block;
      padding: 12px 24px;
      border: 1px solid #ccc;
      border-bottom: none;
      cursor: pointer;
      background: #f9f9f9;
      margin-right: -5px;
      font-weight: 600;
      position: relative;
    }
    .tabs-container > label:hover {
      background: #eaeaea;
    }
    /* underline indicator */
    .tabs-container > label::after {
      content: '';
      position: absolute;
      bottom: -1px;
      left: 0;
      width: 100%;
      height: 3px;
      background: transparent;
      transition: background 0.2s;
    }
    /* checked tab styling */
    .tabs-container > input:checked + label {
      background: #fff2ad;
      border-bottom: 1px solid white;
    }
    .tabs-container > input:checked + label::after {
      background: #007bff;
    }
    /* content panel area */
    .tab-content {
      border: 1px solid #ccc;
      padding: 1rem;
      background-color: white !important;
      width: 100% !important;
    }
    .tab-panel {
      display: none;
    }
    /* show panel when corresponding radio is checked */
    #tab-pending:checked ~ .tab-content #panel-pending,
    #tab-approved:checked ~ .tab-content #panel-approved {
      display: block;
    }
    
    .badge {
      padding: 4px 8px;
      border-radius: 12px;
      font-size: 0.85rem;
    }
    .badge-pending {
      background: #fef3c7;
      color: #b45309;
    }
    .badge-approved {
      background: #d1fae5;
      color: #065f46;
    }
    .custom-width-modal {
			  width: 70% !important;
			  max-width: 100%;
			}

	.Approval-Box
	{
	        background-color: #c0ffeb;
            height: 1.3rem;
            width: 1.3rem;
            border-radius: 2px;
            margin-bottom: -5px;
            box-shadow: 0px 0px 9px #a5a5a5;
    }

  </style>
</head>
<body>
<%
Map<String, List<Object[]>> approvalPendingMap =(Map<String, List<Object[]>>)request.getAttribute("ApprovalPendingList");
Map<String, List<Object[]>> approvedMap =(Map<String, List<Object[]>>)request.getAttribute("ApprovalList");
String fromYear=(String)request.getAttribute("FromYear");
String toYear=(String)request.getAttribute("ToYear");
String fundListApprovedOrNot=(String)request.getAttribute("FundListApprovedOrNot");
String DivisionDetails=(String)request.getAttribute("DivisionDetails");
String redirectedvalue=(String)request.getAttribute("redirectedvalueForward");
String memberType=(String)request.getAttribute("memberType");
%>

<% Map<String, String> roleNamesApproval = new HashMap<>();
       roleNamesApproval.put("DH", "Division Head Recommendation");
       roleNamesApproval.put("CM", "Committee Member Recommendation");
       roleNamesApproval.put("SE", "Subject Expert Recommendation");
       roleNamesApproval.put("CS", "Committee Secretary Noting");
       roleNamesApproval.put("CC", "Committee Chairman Approval");
       roleNamesApproval.put("SC", "Standby Chairman Approval"); %>

<% Map<String, String> roleNamesApproved = new HashMap<>();
       roleNamesApproved.put("DH", "Division Head Recommended");
       roleNamesApproved.put("CM", "Committee Member Recommended");
       roleNamesApproved.put("SE", "Subject Expert Recommended");
       roleNamesApproved.put("CS", "Committee Secretary Noted");
       roleNamesApproved.put("CC", "Committee Chairman Approved");
       roleNamesApproved.put("SC", "Standby Chairman Approved"); %>

<%String success=(String)request.getParameter("resultSuccess");
String failure=(String)request.getParameter("resultFailure");%>


<div class="card-header page-top">
	<div class="row">
	 	<div class="col-md-3"><h5><% if(memberType.contains("CC") || memberType.contains("SC")){ %> Approval
									         <%}else if(memberType.contains("CM") || memberType.contains("DH") || memberType.contains("SE")){ %> Recommend
									         <%}else if(memberType.contains("CS")){ %> Noting
									         <%}else{ %> Recommend<%} %> List</h5></div>
	      <div class="col-md-9">
	    	 <ol class="breadcrumb" style="justify-content: right;">
	    	 <li class="breadcrumb-item"><a href="MainDashBoard.htm"><i class=" fa-solid fa-house-chimney fa-sm"></i> Home </a></li>
	              <li class="breadcrumb-item active" aria-current="page">
	              <% if(memberType.contains("CC") || memberType.contains("SC")){ %> Approval
									         <%}else if(memberType.contains("CM") || memberType.contains("DH") || memberType.contains("SE")){ %> Recommend
									         <%}else if(memberType.contains("CS")){ %> Noting
									         <%}else{ %> Recommend<%} %> List</li>
             </ol>
          </div>
    </div>
</div><!-- Breadecrumb End -->



<div class="page card dashboard-card"> <!-- Page Start -->

    <%
    String Status=(String)request.getParameter("Status");
    String result1=(String)request.getParameter("Failure");
	   if(Status!=null){
	%>
	      <div align="center">
		     <div  class="text-center alert alert-success col-md-8 col-md-offset-2" style="margin-top: 1rem" role="alert">
        	        <%=Status %>
             </div>
   	     </div>
	<%
	   }else if(result1!=null){
	%>
	     <div align="center">
	         <div class="text-center alert alert-danger col-md-8 col-md-offset-2" style="margin-top: 1rem;" role="alert" >
					<%=result1 %>
			 </div>
		</div>
	<%} %>


	<div class="card-body"><!-- Body Part Start -->


		<form action="FundApprovalList.htm" method="POST" autocomplete="off">
			<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
				  <div class="flex-container" style="border-radius: 3px;height: auto !important;padding: 8px;justify-content: flex-end;border-bottom-right-radius: 0px !important;">
					<div class="form-inline" style="justify-content: end;">


							   &nbsp;&nbsp;&nbsp;&nbsp;
						<div class="form-inline" style="">
							 <label id="fromLabel" style="font-weight: bold;">From:&nbsp;&nbsp;&nbsp;</label>
								 <input type="text" style="width: 100px; background-color:white;"  class="form-control"  id="FromYear" onchange="this.form.submit()" <%if(fromYear!=null){%> value="<%=fromYear%>" <%}%> name="FromYear"  required="required" readonly="readonly">
					    </div>
							   &nbsp;&nbsp;&nbsp;&nbsp;
						<div class="form-inline" style="">
							 <label id="toLabel" style="font-weight: bold;">&nbsp;&nbsp;&nbsp;To:&nbsp;&nbsp;&nbsp;</label>
					              <input type="text" style="width: 100px; background-color:white;" class="form-control" id="ToYear"   <%if(toYear!=null){%>value="<%=toYear%>" <%}%>   name="ToYear"  required="required"  readonly="readonly" >
						</div>
					</div>
				</div>
		</form>

		<div class="tabs-container" style="margin-top:7px;">
		    <input type="radio" name="tabs" id="tab-pending">
		    <label for="tab-pending" style="margin-bottom:0px !important;">Fund <% if(memberType.contains("CC") || memberType.contains("SC")){ %> Approval
									         <%}else if(memberType.contains("CM") || memberType.contains("DH") || memberType.contains("SE")){ %> Recommend
									         <%}else if(memberType.contains("CS")){ %> Review
									         <%}else{ %> NA <%} %> Pending</label>
		    <input type="radio" name="tabs" id="tab-approved">
		    <label for="tab-approved" style="margin-bottom:0px !important;">Fund <% if(memberType.contains("CC") || memberType.contains("SC")){ %> Approved
									         <%}else if(memberType.contains("CM") || memberType.contains("DH") || memberType.contains("SE")){ %> Recommended
									         <%}else if(memberType.contains("CS")){ %> Noted
									         <%}else{ %> NA <%} %></label>
		<span style="font-weight: 600;color: #843daf;">&nbsp;&nbsp;&nbsp;  RE - Revised Estimate / FBE - Forecast Budget Estimate</span>

		    <div class="tab-content card">

              <section id="panel-pending" class="tab-panel">
                  <%
                    boolean hasPendingData = false; // Flag to check if any role has data
                    if (approvalPendingMap != null && !approvalPendingMap.isEmpty()) {
                       int sn = 1;
                       for (Map.Entry<String, List<Object[]>> entry : approvalPendingMap.entrySet()) {
                           List<Object[]> roleList = entry.getValue();

                           if (roleList != null && !roleList.isEmpty()) {
                               hasPendingData = true; // At least one table will be shown
                  %>
                               <div style="margin-top: 15px; margin-bottom: 12px;">
                                   <span class="badge badge-primary" style="font-size: 14px;padding: 10px 10px !important;"><%= roleNamesApproval.getOrDefault(entry.getKey(), entry.getKey()) %></span>
                               </div>

                               <div class="table-responsive" style="margin-top: 0.5rem; font-weight: 600;">
                                   <table class="table table-bordered" id="pending_<%= entry.getKey() %>">
                                       <thead>
                                           <tr>
                                               <th>SN</th>
                                               <th style="width: 12%;" class="text-nowrap">Estimate Type</th>
                                               <th>Division</th>
                                               <th class="text-nowrap">Budget Head</th>
                                               <th class="text-nowrap">Nomenclature</th>
                                               <th class="text-nowrap">Item Cost</th>
                                               <th class="text-nowrap">View</th>
                                               <th>Status</th>
                                               <th style="width: 10%;" class="text-nowrap">Action</th>
                                           </tr>
                                       </thead>
                                       <tbody>
                                       <% for (Object[] obj : roleList) { %>
                                           <tr>
                                               <td align="center"><%=sn++ %>.</td>
                                               <td align="center" style="width: 12%;"><%= (obj[1]!=null && obj[1].toString().equalsIgnoreCase("R")) ? "RE" : "FBE" %></td>
                                               <td align="left"><% if(obj[13]!=null){%> <%=obj[13] %> <%if(obj[12]!=null){ %> (<%=obj[12] %>) <%} %> <%}else{ %> - <%} %></td>
                                               <td align="left"><%= (obj[8]!=null) ? obj[8] : "-" %></td>
                                               <td align="left"><%= (obj[14]!=null) ? obj[14] : "-" %></td>
                                               <td align="right"><%=AmountConversion.amountConvertion(obj[17], "R") %></td>
                                               <td align="center">
                                                   <button type="button" class="btn btn-sm btn-outline-primary tooltip-container" onclick="openFundDetailsModal('<%=obj[0] %>', this)" data-tooltip="Fund Request Details and Attachment(s)" data-position="top">
                                                       <i class="fa fa-eye"></i>
                                                   </button>
                                               </td>
                                               <%
                                                   String fundStatus = obj[19] == null ? "NaN" : obj[19].toString();
                                                   String[] fundStatusDetails = CommonActivity.getFundNextStatus(fundStatus, obj[20], obj[22]);
                                                   String dhStatus = fundStatusDetails[0], message = fundStatusDetails[4], statusColor = fundStatusDetails[5];
                                               %>
                                               <td style="width: 215px;" align="center">
                                                   <button type="button" class="btn btn-sm w-100 btn-status greek-style" onclick="openApprovalStatusAjax('<%=obj[0]%>')">
                                                       <div class="form-inline">
                                                           <span style="color:<%=statusColor %>;" > <%=message %> </span> &nbsp;&nbsp;&nbsp;
                                                           <i class="fa-solid fa-arrow-up-right-from-square" style="float: right;color:<%=statusColor %>;"></i>
                                                       </div>
                                                   </button>
                                               </td>
                                               <td align="center">
                                               <%
                                                   String action = ""; String tooltip = ""; boolean showPending = false;
                                                   String roleKey = entry.getKey().toUpperCase();
                                                   switch(roleKey) {
                                                       case "DH": showPending = (dhStatus != null && dhStatus.equalsIgnoreCase("Y")); action = "Recommend"; tooltip = "Preview & Recommend"; break;
                                                       case "CM": case "SE": showPending = (dhStatus != null && !dhStatus.equalsIgnoreCase("Y")); action = "Recommend"; tooltip = "Preview & Recommend"; break;
                                                       case "CS": action = "Noting"; tooltip = "Preview & Note"; break;
                                                       case "CC": action = "Approval"; tooltip = "Preview & Approve"; break;
                                                       case "SC": action = "Approval"; tooltip = "Preview & Approve"; break;
                                                       case "CM-Y": case "SE-Y": case "CS-Y": case "CC-Y": action = "Recommend"; tooltip = "Preview & Recommend"; break;
                                                   }
                                               %>
                                               <% if(showPending) { %>
                                                   <span style="color:#783d00; border-radius:10px; padding:2px 9px; background:#ffe8cc; font-size:11px; font-weight:800;">Recommendation Pending</span>
                                               <% } else if(!action.isEmpty()) { %>
                                                   <form action="#" method="POST" style="display:inline">
                                                       <button type="submit" data-tooltip="<%= tooltip %>" class="btn btn-sm icon-btn tooltip-container" style="padding:6px;border:1px solid #05814d;background:#d3ffe5;" formaction="FundApprovalPreview.htm">
                                                           <%= action %> &nbsp;&#10097;&#10097;
                                                       </button>
                                                       <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
                                                       <input type="hidden" name="FundApprovalIdSubmit" value="<%= obj[0] %>">
                                                       <input type="hidden" name="ParticularMemberType" value="<%= roleKey %>">
                                                   </form>
                                               <% } %>
                                               </td>
                                           </tr>
                                       <% } %>
                                       </tbody>
                                   </table>
                               </div>
                  <%
                           }
                       }
                    }

                    // If Map was null, or Map was empty, or Map had keys but all Lists were empty
                    if (!hasPendingData) {
                  %>
                      <div class="text-danger" style="text-align:center; padding: 20px;font-weight: 600;">No Pending Found</div>
                 <% } %>
              </section>

             <section id="panel-approved" class="tab-panel">
                 <%
                   boolean hasApprovedData = false;
                   if (approvedMap != null && !approvedMap.isEmpty()) {
                      for (Map.Entry<String, List<Object[]>> entry : approvedMap.entrySet()) {
                          List<Object[]> roleList = entry.getValue();

                          if (roleList != null && !roleList.isEmpty()) {
                              hasApprovedData = true;
                              int sN = 1;
                 %>
                              <div style="margin-top: 15px; margin-bottom: 12px;">
                                  <span class="badge badge-primary" style="font-size: 14px;padding: 10px 10px !important;"><%= roleNamesApproved.getOrDefault(entry.getKey(), entry.getKey()) %></span>
                              </div>

                              <div class="table-responsive" style="margin-top: 0.5rem; font-weight: 600;">
                                 <table class="table table-bordered" id="Approval_<%= entry.getKey() %>">
                                     <thead>
                                           <tr>
                                               <th>SN</th>
                                               <th style="width: 12%;" class="text-nowrap">Estimate Type</th>
                                               <th>Division</th>
                                               <th class="text-nowrap">Budget Head</th>
                                               <th class="text-nowrap">Item Nomenclature</th>
                                               <th class="text-nowrap">Item Cost</th>
                                               <th class="text-nowrap">View</th>
                                               <th style="width: 15%;">Status</th>
                                               <th style="width: 5%;">Action</th>
                                           </tr>
                                     </thead>
                                     <tbody>
                                     <% for (Object[] obj : roleList) { %>
                                         <tr>
                                             <td align="center"><%= sN++ %>.</td>
                                             <td align="center" style="width: 12%;"><%= (obj[1]!=null && obj[1].toString().equalsIgnoreCase("R")) ? "RE" : "FBE" %></td>
                                             <td align="left"><% if(obj[13]!=null){%> <%=obj[13] %> <%if(obj[12]!=null){ %> (<%=obj[12] %>) <%} %> <%}else{ %> - <%} %></td>
                                             <td align="left"><%= (obj[8]!=null) ? obj[8] : "-" %></td>
                                             <td align="left"><%= (obj[14]!=null) ? obj[14] : "-" %></td>
                                             <td align="right"><%=AmountConversion.amountConvertion(obj[17], "R") %></td>
                                             <td align="center">
                                                 <button type="button" class="btn btn-sm btn-outline-primary tooltip-container" onclick="openFundDetailsModal('<%=obj[0] %>', this)" data-tooltip="Fund Request Details" data-position="top">
                                                     <i class="fa fa-eye"></i>
                                                 </button>
                                             </td>
                                             <%
                                                 String[] fDetails = CommonActivity.getFundNextStatus(obj[19].toString(), obj[20], obj[22]);
                                             %>
                                             <td style="width: 215px;" align="center">
                                                 <button type="button" class="btn btn-sm w-100 btn-status greek-style" onclick="openApprovalStatusAjax('<%=obj[0]%>')">
                                                     <div class="form-inline">
                                                          <span style="color:<%=fDetails[5] %>;" > <%=fDetails[4] %> </span> &nbsp;&nbsp;&nbsp;
                                                          <i class="fa-solid fa-arrow-up-right-from-square" style="float: right;color:<%=fDetails[5] %>;"></i>
                                                     </div>
                                                 </button>
                                             </td>

                                             <td style="width: 215px;" align="center">
                                             <%
                                                 String status = obj[19] != null ? obj[19].toString() : "";
                                                 String mType = memberType != null ? memberType : "";

                                                 if(status.equalsIgnoreCase("A") && (mType.contains("CC") || mType.contains("CS"))) {
                                             %>
                                                    <img id="noteSheet" onclick="window.open('NoteSheetPrint.htm?fundApprovalId=<%=obj[0]%>', '_blank')" data-tooltip="Note Sheet Download" data-position="left" data-toggle="tooltip" class="btn-sm tooltip-container" src="view/images/note-pad.png" width="45" height="35" style="cursor:pointer; background: transparent; padding: 8px; padding-top: 0px; padding-bottom: 0px;">

                                            <%}else{%> - <% } %>
                                             </td>
                                         </tr>
                                     <% } %>
                                     </tbody>
                                 </table>
                              </div>
                 <%
                          }
                      }
                   }

                   if (!hasApprovedData) { %>
                     <div class="text-center text-danger" style="padding: 20px;font-weight: 600;">
                         No Approved Records Found
                     </div>
                 <% } %>
             </section>
		    </div>
		  </div>
	
	
 </div><!-- Body Part End --> 
			
</div> <!-- Page End -->

</body>

<script type="text/javascript">

<%if(success!=null){%>

showSuccessFlyMessage('<%=success %>');

<%}else if(failure!=null){%>

showFailureFlyMessage('<%=failure %>');

<%}%>

$(document).ready(function(){
	
	var listStatus = '<%=fundListApprovedOrNot %>';
	if(listStatus!=null && listStatus!='')
	{
		if(listStatus == 'A')
		{
			$("#tab-approved").click();
		}
		else if(listStatus == 'F') 
		{
			$("#tab-pending").click();
		}
			
	}
	
});

</script>

<script type="text/javascript">
 $(document).ready(function(){
 	  $("#pending").DataTable({
 	 "lengthMenu": [[5, 10, 25, 50, 75, 100,'-1'],[5, 10, 25, 50, 75, 100,"All"]],
 	 "pagingType": "simple",
 	 "pageLength": 5,
 	 "ordering": true
 });
 });
 
 
 $(document).ready(function(){
	  $("#Approval").DataTable({
	 "lengthMenu": [[5, 10, 25, 50, 75, 100,'-1'],[5, 10, 25, 50, 75, 100,"All"]],
	 "pagingType": "simple",
	 "pageLength": 5,
	 "ordering": true
		});
	});
 </script>

<script>
   $("#FromYear").datepicker({
	   format: "yyyy",
	     viewMode: "years", 
	     minViewMode: "years",
	     autoclose:true,
         updateViewDate: true,
	     changeYear: true,
	     endDate: new Date().getFullYear().toString()
	});
  </script>
			  
  <script>
      $("#FromYear").change(function(){
         var FromYear=$("#FromYear").val();
         var value=parseInt(FromYear)+1;
         $("#ToYear").val(value);
      });
  </script>
  <script src="webresources/js/RpbFundStatus.js"></script>
</html>