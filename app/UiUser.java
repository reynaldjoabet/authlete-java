
import java.io.InvalidClassException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.hibernate.annotations.NaturalId;

import com.fasterxml.jackson.annotation.JsonView;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

class UiUser {

	@Setter
	private long id;

	@Setter
	private boolean local;

	/** The hashed password. */
	@Getter
	@Setter
	private String hashedPassword;

	/** The previous password hashes. */
	@Getter
	@Setter
	private List<String> oldHashedPasswords = new ArrayList<>();

	/** Date of last password change. */
	@Getter
	@Setter
	private Date lastPasswordChangeDate;

	@Setter
	private String username;

	@Setter
	private int level = User.LEVEL_ADMIN;

	/**
	 * Instantiates a new user.
	 */
	protected UiUser() {

	}

	/**
	 * Instantiates a new user.
	 *
	 * @param username the username
	 * @param local true for a local user
	 * @param password the password
	 */
	public UiUser(String username, boolean local, String password) {
		this.username = username;
		this.local = local;
		this.setPassword(password);
	}

	public UiUser(String name, int level) {
		this.username = name;
		this.level = level;
		this.local = false;
	} 
}
