package models;

import java.util.Date;
import java.util.List;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.TableGenerator;

@Entity
public class APIKeys {
	@Id
	@GeneratedValue(strategy = GenerationType.TABLE, generator = "apiGen")
    @TableGenerator(
        name = "apiGen",
        table = "apiGenseq",
        pkColumnValue = "api",
        valueColumnName = "nextApi",
        initialValue = 1,
        allocationSize = 1
    )
	private Long id;
	private String key;
	private Date created;
	@ManyToOne(fetch = FetchType.EAGER)
	private User user;
	private Date lastUsed;
	private Long userid;

	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}
	public Date getCreated() {
		return created;
	}
	public void setCreated(Date created) {
		this.created = created;
	}
	public User getUser() {
		return user;
	}
	public void setUser(User user) {
		this.user = user;
		this.userid = this.user.getId();
	}
	public Date getLastUsed() {
		return lastUsed;
	}
	public void setLastUsed(Date lastUsed) {
		this.lastUsed = lastUsed;
	}
	public Long getUserid() {
		return this.userid;
	}
	private void setUserid(Long userid) {
		this.userid = userid;
	}
	
	
	
	
	

}