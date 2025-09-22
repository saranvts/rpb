package com.vts.rpb.reports.dao;

import java.util.Date;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;

@Repository
public class ReportDaoImpl implements ReportDao
{
	private static final Logger logger=LogManager.getLogger(ReportDaoImpl.class);
	
	@PersistenceContext
	EntityManager manager;
	
	@Value("${MdmDb}")
	private String mdmdb;	
	
	@Override
	public List<Object[]> estimateTypeParticularDivList(String divisionId, String estimateType,String finYear, String loginType,String empId, String budget,String proposedProject, String budgetHeadId, String budgetItemId,
			String fromCost, String toCost,String status,String memberType,int RupeeValue) throws Exception{
		try {

			Query query= manager.createNativeQuery("SELECT f.FundApprovalId, dm.DivisionId, dm.DivisionName, f.EstimateType, f.DivisionId, f.FinYear, f.REFBEYear, f.ProjectId, f.BudgetHeadId, h.BudgetHeadDescription, f.BudgetItemId, i.HeadOfAccounts, i.MajorHead, i.MinorHead, i.SubHead, i.SubMinorHead,f.BookingId, f.CommitmentPayIds, f.ItemNomenclature, f.Justification, ROUND(IFNULL((f.Apr+f.May+f.Jun+f.Jul+f.Aug+f.Sep+f.Oct+f.Nov+f.December+f.Jan+f.Feb+f.Mar)/:rupeeValue,0),2) AS EstimatedCost, f.InitiatingOfficer, e.EmpName, ed.Designation, f.Remarks, f.Status, f.RequisitionDate, dm.DivisionCode,ifa_latest_approver.Remarks AS ChairmanRemarks, attach.Attachments FROM fund_approval f LEFT JOIN  "+mdmdb+".employee e ON e.EmpId=f.InitiatingOfficer LEFT JOIN "+mdmdb+".employee_desig ed ON ed.DesigId=e.DesigId LEFT JOIN tblbudgethead h ON h.BudgetHeadId=f.BudgetHeadId LEFT JOIN tblbudgetitem i ON i.BudgetItemId=f.BudgetItemId LEFT JOIN "+mdmdb+".division_master dm ON dm.DivisionId=:divisionId LEFT JOIN (SELECT att.FundApprovalId,GROUP_CONCAT(CONCAT(att.FileName, '::', att.OriginalFileName, '::', att.Path, '::',att.FundApprovalAttachId) SEPARATOR '||') AS Attachments FROM fund_approval_attach att GROUP BY att.FundApprovalId) attach ON attach.FundApprovalId = f.FundApprovalId LEFT JOIN (SELECT t.FundApprovalId, t.Remarks FROM ibas_fund_approval_trans t INNER JOIN ibas_flow_details fd ON  fd.FlowDetailsId = t.FlowDetailsId AND fd.StatusCode = 'CC' AND fd.StatusType = 'A') ifa_latest_approver ON ifa_latest_approver.FundApprovalId = f.FundApprovalId WHERE f.FinYear=:finYear AND (CASE WHEN 'N'=:budget THEN f.InitiationId = :proposedProject ELSE f.InitiationId = 0 END) AND f.ProjectId=0 AND (CASE WHEN 0=:budgetHeadId THEN 1=1 ELSE f.BudgetHeadId=:budgetHeadId END) AND (CASE WHEN 0=:budgetItemId THEN 1=1 ELSE f.BudgetItemId=:budgetItemId END) AND f.EstimateType=:estimateType AND (CASE WHEN '-1'=:divisionId THEN 1=1 ELSE f.DivisionId=:divisionId END) AND (CASE WHEN 'A'=:loginType THEN 1=1 ELSE (CASE WHEN :memberType='CC' OR :memberType='CS' THEN 1=1 ELSE f.DivisionId IN (SELECT DivisionId FROM "+mdmdb+".employee WHERE EmpId=:empId) END) END) AND (CASE WHEN 'NA'=:statuss THEN 1=1 ELSE f.Status=:statuss END) HAVING EstimatedCost BETWEEN :fromCost AND :toCost ORDER BY f.FundApprovalId DESC");
			
			System.out.println("divisionId****"+divisionId);
			System.out.println("estimateType****"+estimateType);
			System.out.println("finYear****"+finYear);
			System.out.println("loginType****"+loginType);
			System.out.println("empId****"+empId);
			System.out.println("budget****"+budget);
			System.out.println("proposedProject****"+proposedProject);
			System.out.println("budgetHeadId****"+budgetHeadId);
			System.out.println("budgetItemId****"+budgetItemId);
			System.out.println("fromCost****"+fromCost);
			System.out.println("toCost****"+toCost);
			System.out.println("status****"+status);
			System.out.println("memberType****"+memberType);
			System.out.println("RupeeValue****"+RupeeValue);
			
			query.setParameter("divisionId", divisionId);
			query.setParameter("estimateType", estimateType);
			query.setParameter("finYear",finYear);
			query.setParameter("loginType",loginType);
			query.setParameter("empId",empId);
			query.setParameter("budget",budget);
			query.setParameter("proposedProject",proposedProject);
			query.setParameter("budgetHeadId",budgetHeadId);
			query.setParameter("budgetItemId",budgetItemId);
			query.setParameter("fromCost",fromCost);
			query.setParameter("toCost",toCost);
			query.setParameter("statuss",status);
			query.setParameter("memberType",memberType);
			query.setParameter("rupeeValue",RupeeValue);
			return query.getResultList();
			
		}catch (Exception e) {
			logger.error(new Date() +"Inside DAO estimateTypeParticularDivList "+ e);
			e.printStackTrace();
			return null;
		}
	}
	
	
}
