import org.apache.pekko.http.scaladsl.model.Uri
final case class OpenIdConfig(
    issuer: Uri,
    authorizationEndpoint: Uri,
    tokenEndpoint: Uri,
    userInfoEndpoint: Uri,
    jwksUri: Uri,
    deviceAuthorizationEndpoint: Option[Uri] = None,
    endSessionEndpoint: Option[Uri] = None,
    claimsParameterSupported: Option[Boolean] = None,
    claimsSupported: List[String] = Nil,
    grantTypesSupported: List[String] = Nil,
    responseTypesSupported: List[String] = Nil
)
