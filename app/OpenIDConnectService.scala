package oidc

import java.io.IOException

import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jose.JOSEException
import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.http.HTTPResponse
import com.nimbusds.oauth2.sdk.id.{ Issuer, State }
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator
import com.nimbusds.openid.connect.sdk.{ AuthenticationErrorResponse, * }
import com.nimbusds.openid.connect.sdk.claims.*

import scala.jdk.CollectionConverters.*

// http://nemcio.cf/gitbucket/

final class OpenIDConnectService(
)(implicit ec: scala.concurrent.ExecutionContext){



  private val JWK_REQUEST_TIMEOUT = 5000

  private val OIDC_SCOPE = new Scope(
    OIDCScopeValue.OPENID,
    OIDCScopeValue.EMAIL,
    OIDCScopeValue.PROFILE,
    OIDCScopeValue.ADDRESS
  )



}