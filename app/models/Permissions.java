package models;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.TableGenerator;
import jakarta.persistence.Transient;

@Entity
public class Permissions {
	

	@Id
	@GeneratedValue(strategy = GenerationType.TABLE, generator = "permGen")
    @TableGenerator(
        name = "permGen",
        table = "permGenseq",
        pkColumnValue = "perm",
        valueColumnName = "nextPerm",
        initialValue = 1,
        allocationSize = 1
    )
	private Long id;
	private Boolean admin;
	private Boolean assessor;
	private Boolean engagement;
	private Boolean manager;
	private Boolean executive;
	private Boolean remediation;
	private Integer accessLevel;
	
	@Transient
	public static Integer AccessLevelTeamOnly = 1;
	@Transient
	public static Integer AccessLevelAllData = 0;
	@Transient
	public static Integer AccessLevelUserOnly = 2;
	
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	public boolean isAdmin() {
		return admin;
	}
	public void setAdmin(boolean admin) {
		this.admin = admin;
	}
	public boolean isAssessor() {
		return assessor;
	}
	public void setAssessor(boolean assessor) {
		this.assessor = assessor;
	}
	public boolean isEngagement() {
		return engagement;
	}
	public void setEngagement(boolean engagement) {
		this.engagement = engagement;
	}
	public boolean isManager() {
		return manager;
	}
	public void setManager(boolean manager) {
		this.manager = manager;
	}
	public boolean isExecutive() {
		return executive;
	}
	public void setExecutive(boolean executive) {
		this.executive = executive;
	}
	public boolean isRemediation() {
		return remediation;
	}
	public void setRemediation(boolean remediation) {
		this.remediation = remediation;
	}
	public Integer getAccessLevel() {
		if(accessLevel == null)
			return this.AccessLevelAllData;
		else
			return accessLevel;
	}
	public void setAccessLevel(Integer accessLevel) {
		this.accessLevel = accessLevel;
	}
	
	
	
	
	
	
	

}
