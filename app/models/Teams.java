package models;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;


@Entity

public class Teams {
	@Id
	@GeneratedValue
	private Long id;
	private String TeamName;
	
	public Teams(){}
	public Teams(Long id, String name){
		this.id = id;
		this.TeamName = name;
	}
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getTeamName() {
		return TeamName;
	}
	public void setTeamName(String teamName) {
		TeamName = teamName;
	}
	
	

}
