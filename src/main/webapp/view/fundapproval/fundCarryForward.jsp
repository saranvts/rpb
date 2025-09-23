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
<%@ page import="jakarta.servlet.http.HttpSession"%>

<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<jsp:include page="../static/header.jsp"></jsp:include>
<title>Carry Forward Fund</title>
<style>

input::-webkit-outer-spin-button,
input::-webkit-inner-spin-button {
  -webkit-appearance: none;
}
b
{
	font-weight: 600;
}
.select2-selection
{
  text-align: left;
}

.select2-results__option,.select2-selection__rendered
{
	font-weight: 600 !important;
}

.HeadingSpan
{
	font-weight: 600;
	color:rgb(9, 9, 87);
	font-size: 21px;
	font-family: math;
	text-shadow: 0px 0px 2px #2dffc8;
	text-decoration: underline;
}

input[name="ItemNomenclature"]::placeholder {
  color: rgb(9, 9, 87) !important;
  font-weight: 600 !important;
}

.custom-placeholder
{
   font-weight: 600;
   text-align: right;
   margin:5px;
   color:blue !important;
   width: 85% !important;
   transition:transform 0.5s ease;
   transform: scale(1); 
}

.spanClass
{
	font-size:16px;
	color:red;
	font-weight: 600;
}

tr:first-of-type th:first-of-type {
  border-top-left-radius: 4px;
}

tr:first-of-type th:last-of-type {
  border-top-right-radius: 4px;
}

tr:last-of-type th:first-of-type {
  border-bottom-left-radius: 4px;
}

tr:last-of-type th:last-of-type {
  border-bottom-right-radius: 4px;
}

.box-shadow-effect {
    box-shadow: rgb(239, 7, 7) 0px 0px 1px 1px;
  }
  
  
    .checkbox-wrapper-12 {
    position: relative;
    margin-top: -26px;
    margin-right: 13px
  }

  .checkbox-wrapper-12 > svg {
    position: absolute;
    top: -130%;
    left: -170%;
    width: 110px;
    pointer-events: none;
  }

  .checkbox-wrapper-12 * {
    box-sizing: border-box;
  }

  .checkbox-wrapper-12 input[type="checkbox"] {
    -webkit-appearance: none;
    -moz-appearance: none;
    appearance: none;
    -webkit-tap-highlight-color: transparent;
    cursor: pointer;
    margin: 0;
  }

  .checkbox-wrapper-12 input[type="checkbox"]:focus {
    outline: 0;
  }

  .checkbox-wrapper-12 .cbx {
    top: calc(50vh - 12px);
    left: calc(50vw - 12px);
  }

  .checkbox-wrapper-12 .cbx input {
    position: absolute;
    width: 24px;
    height: 24px;
    border: 2px solid #bfbfc0;
    /* border-radius: 50%; */
  }

  .checkbox-wrapper-12 .cbx label {
    width: 24px;
    height: 24px;
    background: none;
    position: absolute;
    transform: translate3d(0, 0, 0);
    pointer-events: none;
  }

  .checkbox-wrapper-12 .cbx svg {
    position: absolute;
    top: 1px;
    margin-left: 3%;
    z-index: 1;
    pointer-events: none;
  }

  .checkbox-wrapper-12 .cbx svg path {
    stroke: #fff;
    stroke-width: 3;
    stroke-linecap: round;
    stroke-linejoin: round;
    stroke-dasharray: 19;
    stroke-dashoffset: 19;
    transition: stroke-dashoffset 0.3s ease;
    transition-delay: 0.2s;
  }

  .checkbox-wrapper-12 .cbx input:checked + label {
    animation: splash-12 0.6s ease forwards;
  }

  .checkbox-wrapper-12 .cbx input:checked + label + svg path {
    stroke-dashoffset: 0;
  }

  .checkbox-wrapper-12 .cbx input:not(:checked) + label {
    animation: unsplash-12 0.6s ease forwards;
  }

  .checkbox-wrapper-12 .cbx input:not(:checked) + label + svg path {
    stroke-dashoffset: 19;
  }
  
  .selectall:checked
  {
 	 box-shadow: 0px 0px 7px green;
  }
  
  .selectall:not(:checked) 
  {
  	box-shadow: 0px 0px 5px red; 
  }
  
  @keyframes splash-12 {
    40% {
      border-radius: 50%;
      background: green;
      box-shadow: 0 -18px 0 -8px green, 16px -8px 0 -8px green, 16px 8px 0 -8px green, 0 18px 0 -8px green, -16px 8px 0 -8px green, -16px -8px 0 -8px green;
    }

    100% {
      border-radius: 0;
      background: green;
      box-shadow: 0 -36px 0 -10px transparent, 32px -16px 0 -10px transparent, 32px 16px 0 -10px transparent, 0 36px 0 -10px transparent, -32px 16px 0 -10px transparent, -32px -16px 0 -10px transparent;
    }
  }

  @keyframes unsplash-12 {
    40% {
      border-radius: 50%;
      background: red;
      box-shadow: 0 -18px 0 -8px red, 16px -8px 0 -8px red, 16px 8px 0 -8px red, 0 18px 0 -8px red, -16px 8px 0 -8px red, -16px -8px 0 -8px red;
    }

    100% {
      border-radius: 0;
      background: none;
      box-shadow: 0 -36px 0 -10px transparent, 32px -16px 0 -10px transparent, 32px 16px 0 -10px transparent, 0 36px 0 -10px transparent, -32px 16px 0 -10px transparent, -32px -16px 0 -10px transparent;
    }
  }
  
  /* Month input feild */ 
.inputBox {
  position: relative;
  width: 16%;
  margin: 3px;
  margin-top: 5px !important;
}

.inputBox input {
  padding: 5px 20px;
  outline: none;
  color: #fff;
  font-size: 1em;
}

.inputBox span {
  position: absolute;
  left: 0;
  color:#6c757d;
  padding: 5px 20px;
  pointer-events: none;
  transition: 0.4s cubic-bezier(0.05, 0.81, 0, 0.93);
  font-weight: 600;
  margin-top: 5px;
}

.inputBox input:focus
{
	text-align: left;
	transform: scale(1.02);
}

.inputBox input:focus ~ span,
.inputBox input:valid ~ span {
  transform: translateX(14px) translateY(-7.5px);
  padding: 0 20px;
  border-radius: 2px;
  background-color: #fffbc0;
  border: 1px solid #9d2f00;
  color:#007eef;
  font-size: 11px;
  margin-top: 1px;
}

.displayPurpose:hover
{
	pointer-events: none;
}  

.dashboard-card {
    min-height: 746px !important;
    max-height: 646px !important;
}

#carryForwardTableDemand td,th
{
	vertical-align: middle !important;
}
#carryForwardTableSupplyOrder td,th
{
	vertical-align: middle !important;
}
#carryForwardTableItem td,th
{
	vertical-align: middle !important;
}

</style>

<style>
.box {
    --border-size: 3px;
    display: inline-block;
    padding: 8px 16px;
    font-size: 17px;
    font-weight: 600;
    color: #046e6e;

    /* Border effect using conic gradients */
    background-image: conic-gradient(from var(--border-angle), #ffffff, #ffffff 50%, #ffffff), conic-gradient(from var(--border-angle), #ffffff 20%, #007deb, #e56100);
    background-size: 
        calc(100% - (var(--border-size) * 2)) 
        calc(100% - (var(--border-size) * 2)), 
        cover;
    background-position: center center;
    background-repeat: no-repeat;

    border-radius: 8px;
    animation: bg-spin 3s linear infinite;
}

@-webkit-keyframes bg-spin {
    to {
        --border-angle: 1turn;
    }
}

@keyframes bg-spin {
    to {
        --border-angle: 1turn;
    }
}

@property --border-angle {
    syntax: "<angle>";
    inherits: true;
    initial-value: 0turn;
}
</style>


<style type="text/css">

.dashboard-card::-webkit-scrollbar {
  display: none;
}

/* For Firefox */
.dashboard-card {
  scrollbar-width: none; /* hides scrollbar in Firefox */
  -ms-overflow-style: none; /* hides scrollbar in IE and Edge */
}

.page.card {
    margin-top: 5px;
    height: auto;          /* grow as needed */
    min-height: 100vh;     /* at least fill the screen */
    max-height: none;      /* no upper limit */
    overflow: visible;     /* allow content to extend outside */
    background-color: transparent !important;
}


</style>

<script type="text/javascript">

function setDynamicHeight(selector) {
    var winHeight = $(window).height();

    $(selector).each(function () {
        var aboveHeight = 0;

        // Calculate total height of all visible elements above this one
        $(this).prevAll(':visible').each(function () {
            aboveHeight += $(this).outerHeight(true);
        });

        var finalHeight = winHeight - aboveHeight;

        $(this).css({
            'height': finalHeight + 'px',
            'overflow-y': 'auto',
            'overflow-x': 'auto',
            'display': 'block'
        });

        console.log(selector, 'above height:', aboveHeight, 'final height:', finalHeight);
    });
}
function setDynamicHeightForTable(selector) {
    var winHeight = $(window).height();

    $(selector).each(function () {
        var aboveHeight = 0;

        // Calculate total height of all visible elements above this one
        $(this).prevAll(':visible').each(function () {
            aboveHeight += $(this).outerHeight(true);
        });

        var finalHeight = winHeight - aboveHeight;

        $(this).css({
            'height': finalHeight + 'px',
            'overflow-y': 'auto',
            'overflow-x': 'auto',
            'display': 'block',

            'scrollbar-width': 'none',   // Firefox
            '-ms-overflow-style': 'none' // IE & Edge
        }).addClass('hide-scrollbar');

        console.log(selector, 'above height:', aboveHeight, 'final height:', finalHeight);
    });
}

function resizeCards() {
    setDynamicHeight('.page.card');
    setDynamicHeight('.common-card');
    setDynamicHeightForTable('#carryForwardTableSupplyOrder');
    setDynamicHeightForTable('#carryForwardTableDemand');
    setDynamicHeightForTable('#carryForwardTableItem');
}

$(document).ready(resizeCards);
$(window).resize(resizeCards);

</script>



</head>
<body>

 <%
     List<Object[]> carryForwardList = (List<Object[]>)request.getAttribute("carryForwardList");
     FundApprovalBackButtonDto fundApprovalDto=(FundApprovalBackButtonDto) session.getAttribute("FundApprovalAttributes");
     String budgetHeadId=(String)request.getAttribute("budgetHeadId");
     String budgetItemId=(String)request.getAttribute("budgetItemId");
     String action=(String)request.getAttribute("action");
     
 %>
 
				<%String BudgetYear="-";
           		  String BudgetYearType="NA";
           		  String FinYear="-";
           		String estimateType=null;
           		String fromYear=null,toYear=null,divisionDetails=null;
           		if(fundApprovalDto!=null)
           		{
           			if(fundApprovalDto.getEstimatedTypeBackBtn()!=null)
           			{
           				if(fundApprovalDto.getEstimatedTypeBackBtn().equalsIgnoreCase("F"))
           				{
           					BudgetYear=fundApprovalDto.getFBEYear();
           					BudgetYearType="FBE Year";
           				}
           				else if(fundApprovalDto.getEstimatedTypeBackBtn().equalsIgnoreCase("R"))
       					{
           					BudgetYear=fundApprovalDto.getREYear();
           					BudgetYearType="RE Year";
       					}
	           		}
           		
           			fromYear=fundApprovalDto.getFromYearBackBtn()!=null ? fundApprovalDto.getFromYearBackBtn() : null;
           			toYear=fundApprovalDto.getToYearBackBtn()!=null ? fundApprovalDto.getToYearBackBtn() : null;
           			
           			if(fromYear!=null && toYear!=null)
       				{
        				FinYear=fundApprovalDto.getFromYearBackBtn()+"-"+fundApprovalDto.getToYearBackBtn();
       				}
           			
           			if(fundApprovalDto.getEstimatedTypeBackBtn()!=null)
           			{
           				estimateType=fundApprovalDto.getEstimatedTypeBackBtn();
           			}
           			
           			if(fundApprovalDto!=null)
           			{
           				divisionDetails=java.net.URLEncoder.encode(fundApprovalDto.getDivisionBackBtn(), "UTF-8");
           			}
           			
           		}%>
<div class="card-header page-top">
	 	<div class="row">
	 	  <div class="col-md-3"><h5>Fund Carry Forward</h5></div>
	      <div class="col-md-9">
	    	 <ol class="breadcrumb" style="justify-content: right;">
	    	 <li class="breadcrumb-item"><a href="MainDashBoard.htm"><i class=" fa-solid fa-house-chimney fa-sm"></i> Home </a></li>
	    	 <li class="breadcrumb-item"><a href="FundRequest.htm?FromYear=<%=fromYear %>&ToYear=<%=toYear %>&DivisionDetails=<%=divisionDetails%>&EstimateType=<%=estimateType %>">Requisition List </a></li>
	         <li class="breadcrumb-item active" aria-current="page">Fund Carry Forward</li>
             </ol>
           </div>
         </div>
       </div> 
       
       <input type="hidden" id="budgetHeadIdHidden" <%if(budgetHeadId!=null){ %> value="<%=budgetHeadId %>" <%} %>>
       <input type="hidden" id="budgetItemIdHidden" <%if(budgetItemId!=null){ %> value="<%=budgetItemId %>" <%} %>>
		
      <form action="FundRequestCarryForward.htm" id="fundForwardListForm" autocomplete="off">
	        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
	         
				<div class="flex-container" style="background-color:#ffedc6;height: auto;width: 99%;margin: auto;box-shadow: 0px 0px 4px #6b797c;">
			           		<div class="form-inline" style="padding: 10px;">
			           		
			           		    <input type="hidden" name="Action" value="<%=action %>">
			           		    <input type="hidden" id="HiddenFinYear" value="<%=FinYear %>">
			           			<label style="font-size: 19px;"><b><%=BudgetYearType %> :&nbsp;</b></label><span class="spanClass"><%=BudgetYear %></span>
			           		</div>
			           		<div class="form-inline" style="padding: 10px;">
			           			<label style="font-size: 19px;"><b>Division :&nbsp;</b></label><span class="spanClass"><% if(fundApprovalDto!=null && fundApprovalDto.getDivisionName()!=null){%><%=fundApprovalDto.getDivisionName() %>&nbsp;<%}else{ %>-<%} %><% if(fundApprovalDto!=null && fundApprovalDto.getDivisionCode()!=null){%>(<%=fundApprovalDto.getDivisionCode() %>)<%}%></span>
			           		</div>
			           		<div class="form-inline" style="padding: 10px;">
			           			<label style="font-size: 19px;"><b>Project :&nbsp;</b></label><span class="spanClass">GEN (GENERAL)</span>
			           		</div>
				           	 <div class="form-inline" style="padding: 10px;">
	                            <label style="font-weight: bold;">Budget Head <span class="mandatory" style="color: red;font-weight: normal;">&nbsp;*</span>&nbsp;&nbsp;</label>
								<select id="selbudgethead" name="budgetHeadId" class="form-control select2 readOnlyClass" required="required" style="width:200px;" data-live-search="true">
	                                <option value="">Select Budget Head</option>
	                      	    </select>                  
	                         </div>
	                         
	                          <div class="form-inline budgetItemDetails" style="padding: 10px;">
                        		<label style="font-weight: bold;">Budget Item <span class="mandatory" style="color: red;font-weight: normal;">&nbsp;*</span>&nbsp;&nbsp;</label>
								<select id="selbudgetitem" name="budgetItemId" class="form-control select2 readOnlyClass" required="required" style="width:400px;" data-live-search="true">
								    <option value="">Select BudgetItem</option>
						 		   </select>              
				             </div>
			           </div>
			       </form>
			       
			       
  <div class="page card dashboard-card" style="margin-top: 5px;">
 
	<div class="card-body" style="background-color:white;">		
								
		<form action="CarryForwardDetails.htm" id="CFForm" autocomplete="off">
	        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
	        <input type="hidden" name="ActionSubmit" value="<%=action %>">
	         <div class="table-responsive" style="margin-top:0px !important;">
	         
	         <%if(action!=null){ %>
	         
	         <% if(action.equalsIgnoreCase("Demand")){ %>
	         
			         <div style="margin-bottom: 8px;">
			         	<span class="box">Existing Demand Details</span>
			         </div>
			         
			         <% if(carryForwardList!=null && carryForwardList.size()>0){ %>
			         <table class="table table-bordered" style="font-weight: 600;width: 100%;margin-bottom: 0px ! important;">
	                   <thead>
	                       <tr style="background-color:#ffda96;color:#000000;">
	                   
		                       <th class="text-nowrap" style="width: 3%;">SN</th>
		                       
		                       <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
		                       <th align="center" style="padding:0px !important;margin:0px !important;background: #edffeb;width: 3%;vertical-align: bottom !important;">
		                        <div class="checkbox-wrapper-12">
								  <div class="cbx">
								    <input class="selectall" type="checkbox" style="height: 16px;width: 16px;"/>
								    <label for="selectall" style="width: 16px;height: 16px;"></label>
								    <svg width="13" height="13" viewbox="0 0 15 14" fill="none">
								      <path d="M2 8.36364L6.23077 12L13 2"></path>
								    </svg>
								  </div>
								</div>

		                       	</th>
		                       <%} %>
		                       
		                       <th class="text-nowrap" style="width: 4%;">Serial No</th>
		                       <th class="text-nowrap" style="width: 10%;">Demand No</th>
		                       <th class="text-nowrap" style="width: 20%;">File No</th>
		                       <th class="text-nowrap" style="width: 30%;">Item Nomenclature</th>
		                       <th class="text-nowrap" style="width: 10%;">Demand Cost</th>
		                       <th class="text-nowrap" style="width: 10%;">DIPL</th>
		                       <th class="text-nowrap" style="width: 10%;">Item Amount</th>
	                       </tr>
	                   </thead>
	                  </table>
	         
			   		<table class="table table-bordered" style="font-weight: 600;width: 100%;" id="carryForwardTableDemand">
	                
	                   <tbody>
	                   <%int sn=0;
	                   long totalSerialNo=0;
	                   
	                     for(Object[] carryForward:carryForwardList){ sn++;totalSerialNo++;%>
	                     
	                     <%if(carryForward[32]!=null){ %>
	                     
		                     <% if((carryForward[32].toString()).equalsIgnoreCase("D")){ %>
		                     
				                  <tr>
			                     
				                    <td class="fundDetails-<%=sn %>" rowspan="1" align="center" style="width: 3%;"><%=sn %>.</td>
			                      
			                      		<td align="center" class="fundDetails-<%=sn %>" style="width: 3%;">
				                    	   <input type="checkbox" class="checkbox" id="cashOutgoCheckbox-<%=totalSerialNo %>" data-table-serialno="<%=sn %>" name="DemandItemOrderDetails" value="<%=totalSerialNo %>">
				                     	   <input type="hidden" name="CFItemNomenclature-<%=totalSerialNo %>" value="<%=carryForward[33]%>">
				                    	   <input type="hidden" name="CFFundRequestId-<%=totalSerialNo %>" value="<%=carryForward[0]%>">
				                     	</td>
				                     	
				                     	<td rowspan="1" align="center" style="width: 4%;"><%if(carryForward[1]!=null){ %> <%=carryForward[1] %> <%}else{ %> - <%} %></td>
				                     	<td align="center" style="width: 10%;"><% if(carryForward[17]!=null){ // Demand Number%><%=carryForward[17] %> <%}else{ %> - <%} %></td>
				                     	<td align="left" style="width: 20%;"><% if(carryForward[36]!=null){ // File No%><%=carryForward[36] %> <%}else{ %> - <%} %></td>
				                     	<td align="left" style="width: 30%;"><% if(carryForward[33]!=null){ // Item Nomenclature%><%=carryForward[33] %> <%}else{ %> - <%} %></td>
				                     	<td align="right" style="width: 10%;"><% if(carryForward[19]!=null){ // Estimated Cost%><%=AmountConversion.amountConvertion(carryForward[19], "R") %> <%}else{ %> - <%} %></td>
				                     	<td align="right" style="width: 10%;">
				                      	<input type="checkbox" class="DemandOrderItemDetails-<%=totalSerialNo %>" name="BookingId-<%=totalSerialNo %>" onclick="IndividualDemandItemsOutStandingCost('<%=totalSerialNo %>','DemandOrderItemDetails')" value="<%=carryForward[16] %>#<%=carryForward[20]!=null ? carryForward[20] : 0 %>" style="display: none;">     <% // Value - BookingId(Demand) and DIPL %>
				                     	<% if(carryForward[20]!=null){ // DIPL%><%=AmountConversion.amountConvertion(carryForward[20], "R") %><%}else{ %> 0.00 <%} %></td>
				                     	<td align="center" style="width: 10%;"><input type="number" readonly="readonly" placeholder="Item Amount" id="CFItemAmount-<%=totalSerialNo%>" name="CFItemAmount-<%=totalSerialNo%>" style="font-weight: 600;" class="form-control" value="0" oninput="limitDigits(this, 15)"></td>
			                      
			                     </tr>
			                     
		                       <tr style="display: none;" class="CashOutgoRow-<%=totalSerialNo %>">
		                       		<td colspan="7">
		                       			  	<div class="row" style="width: 98%;margin:auto;">
							                       	  <div class="flex-container" style="justify-content: left;margin-bottom: 10px !important;;width: 90%;background-color: #ffffff !important;height:auto;">
											            <div class="form-inline" style="font-weight: 600;color:#055505;">
											            Checked DIPL is &nbsp;<span style="color: red;" id="TotalItemOutstanding-<%=totalSerialNo %>"></span>&nbsp; for Selected Demand No&nbsp;<span style="color:red;" id="DisplaySerialNo-<%=totalSerialNo%>"><% if(carryForward[17]!=null){%><%=carryForward[17] %> <%}else{ %> - <%} %></span>
											            </div>
											          </div>
												     
							                       	  <div class="col-md-12" style="margin: auto;padding: 0px;">
							                       	     <div class="form-inline" style="justify-content:center;width: 85%;background-color: #ffefe3;border-radius: 5px;margin:auto;">
							                       		 
							                       		 <%if(estimateType!=null && !estimateType.equalsIgnoreCase("R")){ %>
							                       		 <div class="inputBox"><input required id="AprilMonthForward-<%=totalSerialNo %>" name="CFAprilMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','AprilMonthForward')"><span>April</span></div>
											             <div class="inputBox"><input required id="MayMonthForward-<%=totalSerialNo %>" name="CFMayMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','MayMonthForward')"><span>May</span></div>
											             <div class="inputBox"><input required id="JuneMonthForward-<%=totalSerialNo %>" name="CFJuneMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','JuneMonthForward')"><span>June</span></div>
											             <div class="inputBox"><input required id="JulyMonthForward-<%=totalSerialNo %>" name="CFJulyMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','JulyMonthForward')"><span>July</span></div>
											             <%} %>
											             
											             <div class="inputBox"><input required id="AugustMonthForward-<%=totalSerialNo %>" name="CFAugustMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','AugustMonthForward')"><span>August</span></div>
											             <div class="inputBox"><input required id="SeptemberMonthForward-<%=totalSerialNo %>" name="CFSeptemberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','SeptemberMonthForward')"><span>September</span></div>
											             <div class="inputBox"><input required id="OctoberMonthForward-<%=totalSerialNo %>" name="CFOctoberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','OctoberMonthForward')"><span>October</span></div>
											             <div class="inputBox"><input required id="NovemberMonthForward-<%=totalSerialNo %>" name="CFNovemberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','NovemberMonthForward')"><span>November</span></div>
											             <div class="inputBox"><input required id="DecemberMonthForward-<%=totalSerialNo %>" name="CFDecemberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','DecemberMonthForward')"><span>December</span></div>
											             <div class="inputBox"><input required id="JanuaryMonthForward-<%=totalSerialNo %>" name="CFJanuaryMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','JanuaryMonthForward')"><span>January</span></div>
											             <div class="inputBox"><input required id="FebruaryMonthForward-<%=totalSerialNo %>" name="CFFebruaryMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','FebruaryMonthForward')"><span>February</span></div>
											             <div class="inputBox"><input required id="MarchMonthForward-<%=totalSerialNo %>" name="CFMarchMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','MarchMonthForward')"><span>March</span></div>
							                       	</div>
							                       </div>
								            </div>
		                       		</td>
		                       </tr>
		                     	
		                     <%} %>
	                     
	                     <%} %>
                       
                       <%} %>
                       
                        <tr>
                     	<td colspan="9">
                     		 <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
						       <div class="row" style="justify-content: center !important;width: 90% !important;margin:auto;">
						           <span style="font-size:14px;font-weight:bold;color:#6000ff;">1. Click Submit Button To Transfer Items. <br>
						            2.Choose Only Confirmed DIPL. <br>
						            3.Once Transfered Cannot Be Undo.</span></div>
					         <%} %>
					          <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
					          <div style="justify-content: center;width: 90% !important;margin:auto;text-align: center;padding: 12px;">
						        <button type="button" class="btn btn-sm submit-btn" onclick="SubmitCFDetails()">Submit</button>
						        </div>
						        <%} %>
                     	</td>
                     </tr>
                      
                    </tbody>
                 </table>
                 
                   <%}else{ %>
                   
                   <table class="table table-bordered" style="font-weight: 600;width: 100%;margin-bottom: 0px ! important;">
	                       <tr style="background-color:#ffda96;color:#000000;">
	                   
		                       <th class="text-nowrap" style="width: 3%;">SN</th>
		                       
		                       <th align="center" style="padding:0px !important;margin:0px !important;background: #edffeb;width: 3%;vertical-align: bottom !important;">
		                       	</th>
		                       	
		                       <th class="text-nowrap" style="width: 4%;">Serial No</th>
		                       <th class="text-nowrap" style="width: 10%;">Demand No</th>
		                       <th class="text-nowrap" style="width: 20%;">File No</th>
		                       <th class="text-nowrap" style="width: 30%;">Item Nomenclature</th>
		                       <th class="text-nowrap" style="width: 10%;">Demand Cost</th>
		                       <th class="text-nowrap" style="width: 10%;">DIPL</th>
		                       <th class="text-nowrap" style="width: 10%;">Item Amount</th>
	                       </tr>
	                       
	                        <tr>
	                       		<td colspan="11" align="center" style="font-weight: 600;color:red;">No Record Found</td>
	                       </tr>
	                       
	                  </table>
                     
                      
                       
                    <%} %>
                 
                 <% } else if(action.equalsIgnoreCase("SupplyOrder")){ %>
                 
                  <div style="margin-bottom: 8px;">
			         	<span class="box">Existing Supply Order Details</span>
			         </div>
			        
			        <% if(carryForwardList!=null && carryForwardList.size()>0){ %>
			         
			       <table class="table table-bordered" style="font-weight: 600;width: 100%;margin-bottom: 0px ! important;">
	                   <thead>
	                       <tr style="background-color:#ffda96;color:#000000;">
	                   
		                     <th class="text-nowrap" style="width: 3%;">SN</th>
		                       
		                       <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
		                       <th align="center" style="padding:0px !important;margin:0px !important;background: #edffeb;width: 3%;vertical-align: bottom !important;">
		                        <div class="checkbox-wrapper-12">
								  <div class="cbx">
								    <input class="selectall" type="checkbox" style="height: 16px;width: 16px;"/>
								    <label for="selectall" style="width: 16px;height: 16px;"></label>
								    <svg width="13" height="13" viewbox="0 0 15 14" fill="none">
								      <path d="M2 8.36364L6.23077 12L13 2"></path>
								    </svg>
								  </div>
								</div>

		                       	</th>
		                       <%} %>
		                       
		                       <th class="text-nowrap" style="width: 4%;">Serial No</th>
		                       <th class="text-nowrap" style="width: 10%;">SO No</th>
		                       <th class="text-nowrap" style="width: 10%;">File No</th>
		                       <th class="text-nowrap" style="width: 28%;">Item Nomenclature</th>
		                       <th class="text-nowrap" style="width: 8%;">SO Cost</th>
		                       <th class="text-nowrap" style="width: 8%;">Outstanding Cost</th>
		                       <th class="text-nowrap" style="width: 8%;">COG Amount</th>
		                       <th class="text-nowrap" style="width: 8%;">COG Date</th>
		                       <th class="text-nowrap" style="width: 10%;">Item Amount</th>
	                       </tr>
	                   </thead>
	               </table>
	               
	            <table class="table table-bordered" style="font-weight: 600;width: 100%;" id="carryForwardTableSupplyOrder">
	                  
	               <tbody>
	               
	                   <%int sn=0;String cfType=null;
	                   long currentCommitmentId=0,previousCommitmentId=-1;  // restricting duplicate Supply Order Details 
	                   long commitmentIdCount=0;
	                   long totalSerialNo=0,commitmentSerialNo=0;
	                   
	                  
	                     for(Object[] carryForward:carryForwardList){ %>
	                     
	                     <% cfType = carryForward[32]!=null ? carryForward[32].toString() : null;%>
	                      <% currentCommitmentId = carryForward[21]!=null ? Long.parseLong(carryForward[21].toString()) : 0;%>
	                     
	                     <% if(cfType!=null){ %>
	                     
	                     <%if((cfType.toString()).equalsIgnoreCase("C")){ %>
	                     
	                     <tr>
	                     
	                      	<% if(currentCommitmentId!=previousCommitmentId){ sn++;totalSerialNo++;commitmentSerialNo=0;%>
	                      	
	                      	<% commitmentIdCount = carryForwardList.stream().filter(item -> item[21]!=null && (carryForward[21]).equals(item[21])).count(); %>
	                      	
	                      	    <td class="fundDetails-<%=sn %>" rowspan="<%=commitmentIdCount %>" align="center" style="vertical-align: top !important;width:3%;"><%=sn %>.</td>
	                      	
	                      		<td align="center" rowspan="<%=commitmentIdCount %>" style="vertical-align: top !important;width:3%;">
		                    	   <input type="checkbox" class="checkbox" id="cashOutgoCheckbox-<%=totalSerialNo %>" data-table-serialno="<%=sn %>" name="DemandItemOrderDetails" value="<%=totalSerialNo %>">
		                     	   <input type="hidden" name="CFItemNomenclature-<%=totalSerialNo %>" value="<%=carryForward[34]%>">
		                    	   <input type="hidden" name="CFCommitmentId-<%=totalSerialNo %>" value="<%=carryForward[21]%>">
		                     	</td>
		                     	
		                     	<td align="center" rowspan="<%=commitmentIdCount %>" style="vertical-align: top !important;width: 4%;"><%if(carryForward[1]!=null){ %> <%=carryForward[1] %> <%}else{ %> - <%} %></td>
		                     	<td align="center" rowspan="<%=commitmentIdCount %>" style="vertical-align: top !important;width:10%;"><% if(carryForward[23]!=null){ // SO Number%><%=carryForward[23] %> <%}else{ %> - <%} %></td>
		                     	<td align="left" rowspan="<%=commitmentIdCount %>" style="vertical-align: top !important;width:10%;"><% if(carryForward[22]!=null){ // File No%><%=carryForward[22] %> <%}else{ %> - <%} %></td>
		                     	<td align="left" rowspan="<%=commitmentIdCount %>" style="vertical-align: top !important;width:28%;"><% if(carryForward[34]!=null){ // Item Nomenclature%><%=carryForward[34] %> <%}else{ %> - <%} %></td>
		                     	<td align="right" rowspan="<%=commitmentIdCount %>" style="vertical-align: top !important;width:8%;"><% if(carryForward[26]!=null){ // SO Cost%><%=AmountConversion.amountConvertion(carryForward[26], "R") %> <%}else{ %> - <%} %></td>
		                     	<td align="right" rowspan="<%=commitmentIdCount %>" style="vertical-align: top !important;width:8%;"><% if(carryForward[27]!=null){ // OutCost%><%=AmountConversion.amountConvertion(carryForward[27], "R") %> <%}else{ %> - <%} %></td>
		                     	
		                     	<%} %>
		                     	
		                     	<% commitmentSerialNo++; %>
		                     	
		                     	<td align="right" style="vertical-align: top;width:8%;">
		                     	<input type="checkbox" class="DemandOrderItemDetails-<%=totalSerialNo %>" name="CommitmentPayId-<%=totalSerialNo %>" onclick="IndividualDemandItemsOutStandingCost('<%=totalSerialNo %>','DemandOrderItemDetails')" value="<%=carryForward[28] %>#<%=carryForward[29]!=null ? carryForward[29] : 0 %>" style="display: none;">     <% // Value - CommitmentId(Supplu Order) and Oustanding Cost %>
		                     	<%if(carryForward[29]!=null){ %> <%=AmountConversion.amountConvertion(carryForward[29], "R") %> <%}else{ %> - <%} %></td>
	                     	    <td align="center" style="vertical-align: top !important;width:8%;"><%if(carryForward[30]!=null){ %> <%=DateTimeFormatUtil.getSqlToRegularDate(carryForward[30].toString()) %> <%}else{ %> - <%} %></td>
		                     	
		                     	<% if(currentCommitmentId!=previousCommitmentId){ %>
		                     	<td align="center" rowspan="<%=commitmentIdCount %>" style="width:10%;"><input type="number" readonly="readonly" placeholder="Item Amount" id="CFItemAmount-<%=totalSerialNo%>" name="CFItemAmount-<%=totalSerialNo%>" style="font-weight: 600;" class="form-control" value="0" oninput="limitDigits(this, 15)"></td>
		                     	<%} %>
	                      
	                     </tr>
	                     
	                     <%if(((cfType.toString()).equalsIgnoreCase("C") && commitmentIdCount == commitmentSerialNo)){ %>
	                     
	                     	 <tr style="display: none;" class="CashOutgoRow-<%=totalSerialNo %>">
                       		<td colspan="10">
                       			  	<div class="row" style="width: 98%;margin:auto;">
					                       	  <div class="flex-container" style="justify-content: left;margin-bottom: 10px !important;;width: 90%;background-color: #ffffff !important;height:auto;">
									            <div class="form-inline" style="font-weight: 600;color:#055505;">
									            Total&nbsp;<input type="checkbox" class="displayPurpose" checked="checked">&nbsp;Checked Outstanding Cost : &nbsp;<span style="color: red;" id="TotalItemOutstanding-<%=totalSerialNo %>"></span>&nbsp; for Selected Supply Order No&nbsp;<span style="color:red;" id="DisplaySerialNo-<%=totalSerialNo%>"><%if(carryForward[23]!=null){ %> <%=carryForward[23] %> <%}else{ %> - <%} %></span>
									            </div>
									          </div>
										     
					                       	  <div class="col-md-12" style="margin: auto;padding: 0px;">
					                       	     <div class="form-inline" style="justify-content:center;margin:auto;width: 85%;background-color: #ffefe3;border-radius: 5px;">
					                       		 <div class="inputBox"><input required id="AprilMonthForward-<%=totalSerialNo %>" name="CFAprilMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','AprilMonthForward')"><span>April</span></div>
									             <div class="inputBox"><input required id="MayMonthForward-<%=totalSerialNo %>" name="CFMayMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','MayMonthForward')"><span>May</span></div>
									             <div class="inputBox"><input required id="JuneMonthForward-<%=totalSerialNo %>" name="CFJuneMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','JuneMonthForward')"><span>June</span></div>
									             <div class="inputBox"><input required id="JulyMonthForward-<%=totalSerialNo %>" name="CFJulyMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','JulyMonthForward')"><span>July</span></div>
									             <div class="inputBox"><input required id="AugustMonthForward-<%=totalSerialNo %>" name="CFAugustMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','AugustMonthForward')"><span>August</span></div>
									             <div class="inputBox"><input required id="SeptemberMonthForward-<%=totalSerialNo %>" name="CFSeptemberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','SeptemberMonthForward')"><span>September</span></div>
									             <div class="inputBox"><input required id="OctoberMonthForward-<%=totalSerialNo %>" name="CFOctoberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','OctoberMonthForward')"><span>October</span></div>
									             <div class="inputBox"><input required id="NovemberMonthForward-<%=totalSerialNo %>" name="CFNovemberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','NovemberMonthForward')"><span>November</span></div>
									             <div class="inputBox"><input required id="DecemberMonthForward-<%=totalSerialNo %>" name="CFDecemberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','DecemberMonthForward')"><span>December</span></div>
									             <div class="inputBox"><input required id="JanuaryMonthForward-<%=totalSerialNo %>" name="CFJanuaryMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','JanuaryMonthForward')"><span>January</span></div>
									             <div class="inputBox"><input required id="FebruaryMonthForward-<%=totalSerialNo %>" name="CFFebruaryMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','FebruaryMonthForward')"><span>February</span></div>
									             <div class="inputBox"><input required id="MarchMonthForward-<%=totalSerialNo %>" name="CFMarchMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','MarchMonthForward')"><span>March</span></div>
					                       	</div>
					                       </div>
					         
					                       	</div>
                       		</td>
                       </tr>
	                     
	                     <%} %>
                       
                        <% previousCommitmentId=currentCommitmentId; %>
                       
                       <%} %>
                      
                      <%} %>
                      
                     <%} // List for Loop End %>  
                     
                      <tr>
                     	<td colspan="11">
                     		 <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
						       <div class="row" style="justify-content: center !important;width: 90% !important;margin:auto;">
						           <span style="font-size:14px;font-weight:bold;color:#6000ff;">1. Click Submit Button To Transfer Items. <br>
						            2.Choose Only Confirmed Outstanding Cost. <br>
						            3.Once Transfered Cannot Be Undo.</span></div>
					         <%} %>
					          <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
					          <div style="justify-content: center;width: 90% !important;margin:auto;text-align: center;padding: 12px;">
						        <button type="button" class="btn btn-sm submit-btn" onclick="SubmitCFDetails()">Submit</button>
						        </div>
						        <%} %>
                     	</td>
                     </tr>
                     
                   </tbody>
                   
                 </table>
                 
                       <%}else{ %>
                   
                   <table class="table table-bordered" style="font-weight: 600;width: 100%;margin-bottom: 0px ! important;">
	                   <thead>
	                       <tr style="background-color:#ffda96;color:#000000;">
	                   
		                     <th class="text-nowrap" style="width: 3%;">SN</th>
		                       
		                       <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
		                       <th align="center" style="padding:0px !important;margin:0px !important;background: #edffeb;width: 3%;vertical-align: bottom !important;">
		                        <div class="checkbox-wrapper-12">
								  <div class="cbx">
								    <input class="selectall" type="checkbox" style="height: 16px;width: 16px;"/>
								    <label for="selectall" style="width: 16px;height: 16px;"></label>
								    <svg width="13" height="13" viewbox="0 0 15 14" fill="none">
								      <path d="M2 8.36364L6.23077 12L13 2"></path>
								    </svg>
								  </div>
								</div>

		                       	</th>
		                       <%} %>
		                       
		                       <th class="text-nowrap" style="width: 4%;">Serial No</th>
		                       <th class="text-nowrap" style="width: 10%;">SO No</th>
		                       <th class="text-nowrap" style="width: 10%;">File No</th>
		                       <th class="text-nowrap" style="width: 28%;">Item Nomenclature</th>
		                       <th class="text-nowrap" style="width: 8%;">SO Cost</th>
		                       <th class="text-nowrap" style="width: 8%;">Outstanding Cost</th>
		                       <th class="text-nowrap" style="width: 8%;">COG Amount</th>
		                       <th class="text-nowrap" style="width: 8%;">COG Date</th>
		                       <th class="text-nowrap" style="width: 10%;">Item Amount</th>
	                       </tr>
	                       
	                        <tr style="background-color: white;"> 
	                       		<td colspan="11" align="center" style="font-weight: 600;color:red;">No Record Found</td>
	                       </tr>
	                       
	                   </thead>
	                  </table>
                     
                      
                       
                    <%} %>
                 
                 <%} else if(action.equalsIgnoreCase("Item")){ %>
                 
                  <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
                  	<div style="margin-bottom: 8px;">
			         	<span class="box">Existing Item Details</span>
			         </div>
			         
			         <table class="table table-bordered" style="font-weight: 600;width: 100%;margin-bottom: 0px ! important;">
	                   <thead>
	                       <tr style="background-color:#ffda96;color:#000000;">
	                   
		                       <th class="text-nowrap" style="width: 3%;">SN</th>
		                       
		                       <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
		                       <th align="center" style="padding:0px !important;margin:0px !important;background: #edffeb;width: 3%;vertical-align: bottom !important;">
		                        <div class="checkbox-wrapper-12">
								  <div class="cbx">
								    <input class="selectall" type="checkbox" style="height: 16px;width: 16px;"/>
								    <label for="selectall" style="width: 16px;height: 16px;"></label>
								    <svg width="13" height="13" viewbox="0 0 15 14" fill="none">
								      <path d="M2 8.36364L6.23077 12L13 2"></path>
								    </svg>
								  </div>
								</div>

		                       	</th>
		                       <%} %>
		                       
		                       <th class="text-nowrap" style="width: 10%;">Serial No</th>
		                       <th class="text-nowrap" style="width: 54%;">Item Nomenclature</th>
		                       <th class="text-nowrap" style="width: 10%;">Item Requested</th>
		                       <th class="text-nowrap" style="width: 10%;">Item Balance</th>
		                       <th class="text-nowrap" style="width: 10%;">Item Amount</th>
	                       </tr>
	                   </thead>
	                  </table>
	         
			   		<table class="table table-bordered" style="font-weight: 600;width: 100%;" id="carryForwardTableItem">
	                
	                   <tbody>
	                   <%int sn=0;
	                   long totalSerialNo=0;
	                   
	                     for(Object[] carryForward:carryForwardList){ sn++;totalSerialNo++;%>
	                     
	                     <%if(carryForward[32]!=null){ %>
	                     
		                     <% if((carryForward[32].toString()).equalsIgnoreCase("I")){ %>
		                     
				                  <tr>
			                     
				                    <td class="fundDetails-<%=sn %>" rowspan="1" align="center" style="width: 3%;"><%=sn %>.</td>
			                      
			                      		<td align="center" class="fundDetails-<%=sn %>" style="width: 3%;">
				                    	   <input type="checkbox" class="checkbox" id="cashOutgoCheckbox-<%=totalSerialNo %>" data-table-serialno="<%=sn %>" name="DemandItemOrderDetails" value="<%=totalSerialNo %>">
				                     	   <input type="hidden" name="CFItemNomenclature-<%=totalSerialNo %>" value="<%=carryForward[8]%>">
		                    	   		   <input type="hidden" name="CFFundRequestId-<%=totalSerialNo %>" value="<%=carryForward[0]%>">
				                     	</td>
				                     	
				                     	<td rowspan="1" align="center" style="width: 10%;"><%if(carryForward[1]!=null){ // serial No%> <%=carryForward[1] %> <%}else{ %> - <%} %></td>
				                     	<td align="left" style="width: 54%;"><% if(carryForward[8]!=null){ // Item Nomenclature%><%=carryForward[8] %> <%}else{ %> - <%} %></td>
				                     	<td align="right" style="width: 10%;"><% if(carryForward[11]!=null){ // Item Requested%><%=AmountConversion.amountConvertion(carryForward[11], "R") %> <%}else{ %> - <%} %></td>
				                     	<td align="right" style="width: 10%;">
				                      	<input type="checkbox" class="DemandOrderItemDetails-<%=totalSerialNo %>" name="FundRequestId-<%=totalSerialNo %>" onclick="IndividualDemandItemsOutStandingCost('<%=totalSerialNo %>','DemandOrderItemDetails')" value="<%=carryForward[0] %>#<%=carryForward[12]!=null ? carryForward[12] : 0 %>" style="display: none;">
				                     	<% if(carryForward[12]!=null){ // Item Balance%><%=AmountConversion.amountConvertion(carryForward[12], "R") %><%}else{ %> 0.00 <%} %></td>
				                     	<td align="center" style="width: 10%;"><input type="number" readonly="readonly" placeholder="Item Amount" id="CFItemAmount-<%=totalSerialNo%>" name="CFItemAmount-<%=totalSerialNo%>" style="font-weight: 600;" class="form-control" value="0" oninput="limitDigits(this, 15)"></td>
			                      
			                     </tr>
			                     
		                       <tr style="display: none;" class="CashOutgoRow-<%=totalSerialNo %>">
		                       		<td colspan="7">
		                       			  	<div class="row" style="width: 98%;margin:auto;">
							                       	  <div class="flex-container" style="justify-content: left;margin-bottom: 10px !important;;width: 90%;background-color: #ffffff !important;height:auto;">
											            <div class="form-inline" style="font-weight: 600;color:#055505;">
											            Checked Item is &nbsp;<span style="color: red;" id="TotalItemOutstanding-<%=totalSerialNo %>"></span>&nbsp; for Selected Serial No&nbsp;<span style="color:red;" id="DisplaySerialNo-<%=totalSerialNo%>"><% if(carryForward[1]!=null){%><%=carryForward[1] %> <%}else{ %> - <%} %></span>
											            </div>
											          </div>
												     
							                       	  <div class="col-md-12" style="margin: auto;padding: 0px;">
							                       	     <div class="form-inline" style="justify-content:center;width: 85%;background-color: #ffefe3;border-radius: 5px;margin:auto;">
							                       		 <div class="inputBox"><input required id="AprilMonthForward-<%=totalSerialNo %>" name="CFAprilMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','AprilMonthForward')"><span>April</span></div>
											             <div class="inputBox"><input required id="MayMonthForward-<%=totalSerialNo %>" name="CFMayMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','MayMonthForward')"><span>May</span></div>
											             <div class="inputBox"><input required id="JuneMonthForward-<%=totalSerialNo %>" name="CFJuneMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','JuneMonthForward')"><span>June</span></div>
											             <div class="inputBox"><input required id="JulyMonthForward-<%=totalSerialNo %>" name="CFJulyMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','JulyMonthForward')"><span>July</span></div>
											             <div class="inputBox"><input required id="AugustMonthForward-<%=totalSerialNo %>" name="CFAugustMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','AugustMonthForward')"><span>August</span></div>
											             <div class="inputBox"><input required id="SeptemberMonthForward-<%=totalSerialNo %>" name="CFSeptemberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','SeptemberMonthForward')"><span>September</span></div>
											             <div class="inputBox"><input required id="OctoberMonthForward-<%=totalSerialNo %>" name="CFOctoberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','OctoberMonthForward')"><span>October</span></div>
											             <div class="inputBox"><input required id="NovemberMonthForward-<%=totalSerialNo %>" name="CFNovemberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','NovemberMonthForward')"><span>November</span></div>
											             <div class="inputBox"><input required id="DecemberMonthForward-<%=totalSerialNo %>" name="CFDecemberMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','DecemberMonthForward')"><span>December</span></div>
											             <div class="inputBox"><input required id="JanuaryMonthForward-<%=totalSerialNo %>" name="CFJanuaryMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','JanuaryMonthForward')"><span>January</span></div>
											             <div class="inputBox"><input required id="FebruaryMonthForward-<%=totalSerialNo %>" name="CFFebruaryMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','FebruaryMonthForward')"><span>February</span></div>
											             <div class="inputBox"><input required id="MarchMonthForward-<%=totalSerialNo %>" name="CFMarchMonth-<%=totalSerialNo %>" class="form-control custom-placeholder ForwardAmount-<%=totalSerialNo %>" onkeydown="preventInvalidInput(event)" onkeyup="calculateForwardItemAmount('<%=totalSerialNo %>','MarchMonthForward')"><span>March</span></div>
							                       	</div>
							                       </div>
								            </div>
		                       		</td>
		                       </tr>
		                     	
		                     <%} %>
	                     
	                     <%} %>
                       
                       <%} %>
                       
                        <tr>
                     	<td colspan="9">
                     		 <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
						       <div class="row" style="justify-content: center !important;width: 90% !important;margin:auto;">
						           <span style="font-size:14px;font-weight:bold;color:#6000ff;">1. Click Submit Button To Transfer Items. <br>
						            2.Choose Only Confirmed Items. <br>
						            3.Once Transfered Cannot Be Undo.</span></div>
					         <%} %>
					          <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
					          <div style="justify-content: center;width: 90% !important;margin:auto;text-align: center;padding: 12px;">
						        <button type="button" class="btn btn-sm submit-btn" onclick="SubmitCFDetails()">Submit</button>
						        </div>
						        <%} %>
                     	</td>
                     </tr>
                      
                    </tbody>
                 </table>
                 
                 <%}else{ %>
                 
                 <table class="table table-bordered" style="font-weight: 600;width: 100%;margin-bottom: 0px ! important;">
	                   <thead>
	                       <tr style="background-color:#ffda96;color:#000000;">
	                   
		                       <th class="text-nowrap" style="width: 3%;">SN</th>
		                       
		                       <%if(carryForwardList!=null && carryForwardList.size()>0){ %>
		                       <th align="center" style="padding:0px !important;margin:0px !important;background: #edffeb;width: 3%;vertical-align: bottom !important;">
		                        <div class="checkbox-wrapper-12">
								  <div class="cbx">
								    <input class="selectall" type="checkbox" style="height: 16px;width: 16px;"/>
								    <label for="selectall" style="width: 16px;height: 16px;"></label>
								    <svg width="13" height="13" viewbox="0 0 15 14" fill="none">
								      <path d="M2 8.36364L6.23077 12L13 2"></path>
								    </svg>
								  </div>
								</div>

		                       	</th>
		                       <%} %>
		                       
		                       <th class="text-nowrap" style="width: 10%;">Serial No</th>
		                       <th class="text-nowrap" style="width: 54%;">Item Nomenclature</th>
		                       <th class="text-nowrap" style="width: 10%;">Item Requested</th>
		                       <th class="text-nowrap" style="width: 10%;">Item Balance</th>
		                       <th class="text-nowrap" style="width: 10%;">Item Amount</th>
	                       </tr>
	                       
	                   </thead>
	                   
	                   <tbody>
	                   
	                        <tr>
                       	<td colspan="11" align="center" style="font-weight: 600;color:red;">No Record Found</td>
                       </tr>
	                   </tbody>
	                  </table>
                 
                 <%} %>
                 
                 <%} %>
                 
               <%} %>
                 
               </div>
		    </form>
	     </div>
	   </div>
			       
</body>

<script type="text/javascript">

$(document).ready(function(){
	
    $('.selectall').on('click',function(){
    	
        if(this.checked){
        	
        	//Remove checked Selection
        	$('.checkbox').each(function(){
    			if(this.checked)
    			{
    				var serialNo=$(this).val();
    				 var tableSerialNo=$(this).attr("data-table-serialno"); 
    	        	 let fundDetailsRowSpan = parseInt($('.fundDetails-' + tableSerialNo).attr('rowspan')) || 1;
    	        		
   	        		 // expanding rowspan for Hidden row
   	    			 $('.fundDetails-' + tableSerialNo).attr('rowspan', fundDetailsRowSpan - 1);
    				
    				$('.DemandOrderItemDetails-'+ serialNo).each(function() {
    		            this.checked = false;
    		        });
    				$("#TotalItemOutstanding-"+serialNo).html(0);
    				$(".CashOutgoRow-"+ serialNo + ',.DemandOrderItemDetails-'+ serialNo).hide();
    			}
            });
        	
        	// check All the Checkbox
            $('.checkbox').each(function(){
                this.checked = true;
                var TotalItemCost=parseFloat(0);
                var serialNo=$(this).val();
                var tableSerialNo=$(this).attr("data-table-serialno"); 
        		let fundDetailsRowSpan = parseInt($('.fundDetails-' + tableSerialNo).attr('rowspan')) || 1;
        		
        		// expanding rowspan for Hidden row
    			$('.fundDetails-' + tableSerialNo).attr('rowspan', fundDetailsRowSpan + 1);
        		
                $(".CashOutgoRow-"+ serialNo +',.DemandOrderItemDetails-'+ serialNo).fadeIn();
    			$('.DemandOrderItemDetails-'+ serialNo).each(function() {
    		            this.checked = true;
    		            var checkedValue = $(this).val();
    		            if(checkedValue)
    		            	{
    		            		checkedValue=checkedValue.split("#")[1];
    		            		if(checkedValue)
    		            			{
    		            				TotalItemCost=TotalItemCost+parseFloat(checkedValue);
    		            			}
    		            	}
    		        });
    			$("#TotalItemOutstanding-"+ serialNo).html(TotalItemCost);
            });
        }else{
             $('.checkbox').each(function(){
                this.checked = false;
                var serialNo=$(this).val();
                var tableSerialNo=$(this).attr("data-table-serialno"); 
        		let fundDetailsRowSpan = parseInt($('.fundDetails-' + tableSerialNo).attr('rowspan')) || 1;
        		
        		// expanding rowspan for Hidden row
    			$('.fundDetails-' + tableSerialNo).attr('rowspan', fundDetailsRowSpan - 1);
				$('.DemandOrderItemDetails-'+ serialNo).each(function() {
		            this.checked = false;
		        });
				$("#TotalItemOutstanding-"+serialNo).html(0);
				$(".CashOutgoRow-"+ serialNo + ',.DemandOrderItemDetails-'+ serialNo).hide();
            });
        }
        
        resizeCards();
    });
    
    $('.checkbox').on('click',function(){
    	let serialNo = $(this).val();
    	if(this.checked)
    		{
	    		var tableSerialNo=$(this).attr("data-table-serialno"); 
	    		let fundDetailsRowSpan = parseInt($('.fundDetails-' + tableSerialNo).attr('rowspan')) || 1;
	    		
	    		// expanding rowspan for Hidden row
				$('.fundDetails-' + tableSerialNo).attr('rowspan', fundDetailsRowSpan + 1);
    			$(".CashOutgoRow-"+ serialNo+',.DemandOrderItemDetails-'+ serialNo).fadeIn();
    			var TotalItemCost=parseFloat(0);
    			$('.DemandOrderItemDetails-'+ serialNo).each(function() {
    		            this.checked = true;
    		            var checkedValue = $(this).val();
    		            if(checkedValue)
    		            	{
    		            		checkedValue=checkedValue.split("#")[1];
    		            		if(checkedValue)
   		            			{
   		            				TotalItemCost=TotalItemCost+parseFloat(checkedValue);
   		            			}
    		            	}
    		        });
    			
    			$("#TotalItemOutstanding-"+ serialNo).html(TotalItemCost);
    			
    		}
    	else
    		{
	    		var tableSerialNo=$(this).attr("data-table-serialno"); 
	    		let fundDetailsRowSpan = parseInt($('.fundDetails-' + tableSerialNo).attr('rowspan')) || 1;
	    		
	    		// expanding rowspan for Hidden row
				$('.fundDetails-' + tableSerialNo).attr('rowspan', fundDetailsRowSpan - 1);
    			$('.DemandOrderItemDetails-'+ serialNo).each(function() {
		            this.checked = false;
		        });
    			$("#TotalItemOutstanding-"+ serialNo).html(0);
    			$(".CashOutgoRow-"+ serialNo + ',.DemandOrderItemDetails-'+ serialNo).hide();
    			
    		}
    	
        if($('.checkbox:checked').length == $('.checkbox').length){
            $('.selectall').prop('checked',true);
        }else{
            $('.selectall').prop('checked',false);
        }
        
        resizeCards();
    });
    
});


function calculateForwardItemAmount(count,MonthId)
{
	var ErrorStatus=0;
	var List= ForwardItemArrayList('ForwardAmount',count);
	var TotalCOGAmount=ForwardItemAddList(List);
		
		var TotalItemOS=$("#TotalItemOutstanding-"+count).text();
		if(TotalItemOS)
		{
			TotalItemOS=parseFloat(TotalItemOS);
		}
		
		if(TotalItemOS<parseFloat(TotalCOGAmount))
		{
			alert("Entered COG Should Not More Than Checked COG..!");
			$("#"+MonthId+"-"+count).val('');
			var List= ForwardItemArrayList('ForwardAmount',count);
			var TotalCOGAmount=ForwardItemAddList(List);
			$("#CFItemAmount-"+count).val(TotalCOGAmount);
			ErrorStatus=1;
		}
		else
			{
				$("#CFItemAmount-"+count).val(TotalCOGAmount);
			}
		
		if(ErrorStatus==1)
		  {
		    $("#"+MonthId+"-"+count).focus();
			$('head').append($('<style> '+"#"+MonthId+"-"+count+':focus { box-shadow: 0 0 4px red !important;border-color: #bf1002 !important; }</style>').attr('class', 'TextBoxBorderRed'));
	 	  }
		  else
			{
				 $(".TextBoxBorderRed,.TextBoxBorderBlue").remove();
				 $('head').append($('<style> '+"#"+MonthId+"-"+count+':focus { box-shadow: 0 0 0 .2rem rgba(0, 123, 255, .25);border-color: #80bdff; }</style>').attr('class', 'TextBoxBorderBlue'));
			}
		
	}


function IndividualDemandItemsOutStandingCost(count,ClassName)
{
	var List= arrayList(ClassName,count);
	var TotalCOGAmount=AddList(List);
	$("#TotalItemOutstanding-"+count).html(TotalCOGAmount);
	
}

	//get all data related to checked Outstanding Cost className and push to array
	function arrayList(ClassName, count) {
	    var List = new Array();
	    $('input.' + ClassName + '-' + count).each(function() {
	        if($(this).prop('checked')) {
	            List.push($(this).val());
	        }
	    });
	    return List;
	}
	
	//suming the checked Outstanding Cost array list data
	function AddList(List)
	{
		var TotalCOGAmount=0;
		if(List!=null && List.length !== 0)
		{
			for(var i=0;i<List.length;i++)
		    {
				if(List[i]!='' && List[i].split("#")!=null && List[i].split("#")[1]!=null)
				{
					TotalCOGAmount=parseFloat(TotalCOGAmount)+parseFloat(List[i].split("#")[1]);
				}
			}
		}
		return TotalCOGAmount;
	}
	
	//suming the Forward Item array list data
	function ForwardItemAddList(List)
	{
		var TotalCOGAmount=0;
		if(List!=null && List.length !== 0)
		{
			for(var i=0;i<List.length;i++)
		    {
				if(List[i]!='')
				{
					TotalCOGAmount=parseFloat(TotalCOGAmount)+parseFloat(List[i]);
				}
			}
		}
		return TotalCOGAmount;
	}
	
	// get all data related to ForwardItem className and push to array
	function ForwardItemArrayList(ClassName, count) {
	    var List = new Array();
	    $('input.' + ClassName + '-' + count).each(function() {
	            List.push($(this).val());
	    });
	    return List;
    }
	
function calculateForwardItemAmount(count,MonthId)
{
	var ErrorStatus=0;
	var List= ForwardItemArrayList('ForwardAmount',count);
	var TotalCOGAmount=ForwardItemAddList(List);
		
		var TotalItemOS=$("#TotalItemOutstanding-"+count).text();
		if(TotalItemOS)
		{
			TotalItemOS=parseFloat(TotalItemOS);
		}
		
		if(TotalItemOS<parseFloat(TotalCOGAmount))
		{
			alert("Entered COG Should Not More Than Checked COG..!");
			$("#"+MonthId+"-"+count).val('');
			var List= ForwardItemArrayList('ForwardAmount',count);
			var TotalCOGAmount=ForwardItemAddList(List);
			$("#CFItemAmount-"+count).val(TotalCOGAmount);
			ErrorStatus=1;
		}
		else
			{
				$("#CFItemAmount-"+count).val(TotalCOGAmount);
			}
		
		if(ErrorStatus==1)
		  {
		    $("#"+MonthId+"-"+count).focus();
			$('head').append($('<style> '+"#"+MonthId+"-"+count+':focus { box-shadow: 0 0 4px red !important;border-color: #bf1002 !important; }</style>').attr('class', 'TextBoxBorderRed'));
	 	  }
		  else
			{
				 $(".TextBoxBorderRed,.TextBoxBorderBlue").remove();
				 $('head').append($('<style> '+"#"+MonthId+"-"+count+':focus { box-shadow: 0 0 0 .2rem rgba(0, 123, 255, .25);border-color: #80bdff; }</style>').attr('class', 'TextBoxBorderBlue'));
			}
		
	}
	
	
function preventInvalidInput(event) {
    const invalidChars = ['e', 'E', '+', '-', '.'];
    if (invalidChars.includes(event.key)) {
        event.preventDefault();
    }
}		

</script>

<script type="text/javascript">

function SubmitCFDetails()
{
	var isSerialNoChecked=0,isItemChecked=0,statusCode=0,statusMessage='';
	$('.checkbox').each(function(){
		if(this.checked)
		{
			isSerialNoChecked=1;
			var serialNo=$(this).val();
			var TotalSelectedItemCost=0;
			$('.DemandOrderItemDetails-'+serialNo).each(function() {
				if($(this).prop("checked"))
				{
				    isItemChecked=1;
				    var checkedValue = $(this).val();
		            if(checkedValue)
	            	{
	            		checkedValue=checkedValue.split("#")[1];
	            		if(checkedValue)
            			{
            				TotalSelectedItemCost=TotalSelectedItemCost+parseFloat(checkedValue);
            			}
	            	}
				}
	        });
			
			var List= ForwardItemArrayList("ForwardAmount",serialNo);
	        var totalMontCOGAmount=ForwardItemAddList(List);
			
	        if(totalMontCOGAmount==0)
	        	{
		        	statusCode=-1;
					var serialNo=$("#DisplaySerialNo-"+serialNo).html();
					statusMessage="Select/Checked Serial No "+serialNo+" outstanding cost/Demand Cost/Item Balance should not be empty..!";
					return false;
	        	}
	        else if(TotalSelectedItemCost < totalMontCOGAmount)
				{
					statusCode=-1;
					var serialNo=$("#DisplaySerialNo-"+serialNo).html();
					statusMessage="Select/Checked Serial No "+serialNo+" outstanding cost/Demand Cost should not more than Total Month COG..!";
					return false;
				}
		}
    });
	
	if(isSerialNoChecked==0)
		{
			alert("Select/Check at least one Demand/Supply Order..!");
		}
	else if(isItemChecked==0)
		{
			alert("Select/Check at least one outstanding cost/Demand Cost from serial number..!");
		}
	else if(statusCode==-1)
		{
			alert(statusMessage);
		}
	else
		{
			var form=$('#CFForm');
			if(form)
				{
					var finYear=$("#HiddenFinYear").val();
					if(confirm("Are You Sure To Carry Forward The Supply Order/Demand To Financial Year "+finYear+" ..?"))
					{
						form.submit();
					}
				}
		}
	}

</script>


<script type="text/javascript">

$(document).ready(function(event) {
	
	var projectDetails= '0#GEN#GENERAL';
	var budgetHeadId = $("#budgetHeadIdHidden").val();
	var budgetItemId = $("#budgetItemIdHidden").val();
	
	
		$.get('GetBudgetHeadList.htm', {
			ProjectDetails : projectDetails
		}, function(result) {
			
			$('#selbudgethead').find('option').remove();
			if(budgetHeadId=='-1')
			{
				$('#selbudgethead').append('<option value="-1" selected="selected"> All </option>');
			}
			else
			{
				$('#selbudgethead').append('<option value="-1"> All </option>');
			}
			
			var result = JSON.parse(result);
			var htmlContent='';
			$.each(result, function(key, value) {
				 if(value.budgetHeadId== budgetHeadId)
				 {
					 htmlContent='<option value="'+value.budgetHeadId+'" selected="selected">'+value.budgetHeaddescription+'</option>';
				 }
				 else
					{
					   htmlContent="<option value="+value.budgetHeadId+">"+  value.budgetHeaddescription+ "</option>";
					}
				 $("#selbudgethead").append(htmlContent);
				 
				 if(budgetHeadId=='-1')
				 {
					 $(".budgetItemDetails").hide();
				 }
				 else
				 {
					 SetBudgetItem(budgetItemId,'L'); // onload
				 }
				 
			});
			
		});
	});

		<!------------------Select Budget Item using Ajax-------------------->
		
		$('#selbudgethead').change( function(event) {
			var budgetItemId = $("#budgetItemIdHidden").val();
			SetBudgetItem(budgetItemId,'S');  // onchange submit
		});
		
		$('#selbudgetitem').change( function(event) {
			var form=$("#fundForwardListForm");
			if(form)
			{
				form.submit();
			}
		});
		
		function SetBudgetItem(budgetItemId,submitType)
		{
			var project= '0#GEN#GENERAL'; 
			var budgetHeadId = $("select#selbudgethead").val();
			$(".budgetItemDetails").show();
			
			$.get('SelectbudgetItem.htm', {
			 projectid : project,
			 budgetHeadId : budgetHeadId
			}, function(responseJson) {
				
				$('#selbudgetitem').find('option').remove();
				if(budgetItemId=='-1')
				{
					$("#selbudgetitem").append("<option selected value='-1'> All </option>");
				}
				else
				{
					$("#selbudgetitem").append("<option selected value='-1'> All </option>");
				}
				
				var result = JSON.parse(responseJson);
				$.each(result, function(key, value) {
					
					if(budgetItemId!=null && budgetItemId==value.budgetItemId)
					{
						$("#selbudgetitem").append("<option selected value="+value.budgetItemId+" >"+ value.headOfAccounts+"  ["+value.subHead+"]</option>");
					}
					else
					{
						$("#selbudgetitem").append("<option value="+value.budgetItemId+" >"+ value.headOfAccounts+"  ["+value.subHead+"]</option>");
					}
					
					if(submitType!=null)
					{
						if(submitType == 'S')
						{
							var form=$("#fundForwardListForm");
							if(form)
							{
								form.submit();
							}
						}
					}
					
				});
			});
		}

</script>

</html>