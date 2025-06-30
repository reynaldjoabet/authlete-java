package controllers.authorizers;

import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.authorization.authorizer.ProfileAuthorizer;
import org.pac4j.core.authorization.authorizer.RequireAllRolesAuthorizer;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.profile.UserProfile;
import java.util.List;
import java.util.Set;

public class DataOwnerRoleAuthorizer extends ProfileAuthorizer {



@Override
public boolean isProfileAuthorized(WebContext context,SessionStore sessionStore,UserProfile profile) {
		if (profile == null) {
			return false;
		}
		Set<String> roles = profile.getRoles();
         System.out.println("Is DataOwnerRoleAuthorizer profile authorised was called:"+ roles.contains("Constants.DATA_OWNER_ROLE"));
		return roles.contains("DATA_OWNER_ROLE");


	}

@Override
    public boolean isAuthorized(WebContext context,SessionStore sessionStore,List<UserProfile> profiles) {
		if (profiles.isEmpty()) {
			return false;
		}
		Set<String> roles = profiles.getFirst().getRoles();
		//return roles.contains("DATA_OWNER_ROLE");

     System.out.println("Is  DataOwnerRoleAuthorizer authorised was called:"+isAnyAuthorized(context, sessionStore,profiles));
     return isAnyAuthorized(context, sessionStore,profiles);
	}

}