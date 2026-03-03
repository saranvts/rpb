package com.vts.rpb.fundapproval.modal;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity(name = "fund_approval_attach_revision")
public class FundApprovalAttachRev {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "FundApprovalAttachRevId")
	private long fundApprovalAttachRevId;
	
	@Column(name = "FundApprovalAttachId")
	private long fundApprovalAttachId;
	
	@Column(name = "FundApprovalId")
	private long fundApprovalId;

	@Column(name = "Path", length = 255)
	private String Path;
	
	@Column(name = "FileName", length = 100)
	private String FileName;
	
	@Column(name = "OriginalFileName", length = 255)
	private String OriginalFileName;
	
	@Column(name = "RevisionNo")
	private Integer revisionNo;

	@Column(name = "CreatedBy", length = 100)
	private String CreatedBy;
	
	@Column(name = "CreatedDate")
	private LocalDateTime CreatedDate;
}
