package services.auth
import services.auth.Access.*
object AccessGroups {
  val CROSS_ORG_ACCESS: Set[Access] =
    Set(
      CREATE_ORGS,
      DELETE_ORG,
      READ_OTHER_ORGS,
      WRITE_OTHER_ORGS,
      CREATE_IN_OTHER_ORGS,
      SET_IBM_ORG_TYPE,
      ADMIN,
      NEVER_ALLOWED
    )
}
