package com.vts.rpb.fundapproval.modal;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity(name ="ibas_fund_approval_trans_revision")
public class FundApprovalTransRev {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "FundApprovalTransRevId")
	private long fundApprovalTransRevId;
	
	@Column(name = "FundApprovalId")
	private long fundApprovalId;
	
	@Column(name = "MemberLinkedId")
	private long memberLinkedId;
	
	@Column(name = "FlowDetailsId")
	private long flowDetailsId;
	
	@Column(name = "Remarks", length = 255)
	private String remarks;
	
	@Column(name = "Role", length = 50)
	private String role;
	
	@Column(name = "RevisionNo")
	private Integer revisionNo;

	@Column(name = "ActionBy")
	private long actionBy;
	
	@Column(name = "ActionDate")
	private LocalDateTime actionDate;
	

}
