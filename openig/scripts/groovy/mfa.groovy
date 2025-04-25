import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.forgerock.json.jose.builders.JwtBuilderFactory
import org.forgerock.json.jose.jws.SignedJwt

def jwt=contexts["sts"]!=null?contexts["sts"].issuedToken:null

//check if JWT is present in the request
if (jwt == null || "".equalsIgnoreCase(jwt)) { 
    response = new Response(Status.UNAUTHORIZED)
    response.headers.add("Content-Type", "application/json; charset=UTF-8")
    response.entity=new org.forgerock.json.JsonValue(["error": "Missing JWT"])
    return response
}

//calculate the location to redirect for MFA authentication
String newLocation = location + URLEncoder.encode(contexts.router.originalUri.toString(), StandardCharsets.UTF_8);

try {
    //parse JWT
    def claims = new JwtBuilderFactory().reconstruct(jwt, SignedJwt.class).getClaimsSet()
    def loginUrl = claims.getClaim("FullLoginURL")
    def authInstant = claims.getClaim("authInstant")
    def loginUrlFragment = "authIndexValue=" + requiredChain

    //chefk if the user login url contains totp service
    if(!loginUrl.contains(loginUrlFragment)){
        logger.warn("Login URL does not contain the expected fragment: " + loginUrlFragment)
        response = new Response(Status.FOUND)
        response.headers.add("Location", newLocation)
        return response
    }

    //check auth time
    Instant instant = Instant.parse(authInstant);
    long epochMillisTimeout = instant.toEpochMilli() + timeoutSec * 1000;
    if (epochMillisTimeout < System.currentTimeMillis()) {
        logger.warn("Auth time expired at: " + new Date(epochMillisTimeout))
        response = new Response(Status.FOUND)
        response.headers.add("Location", newLocation)
        return response
    }
    
} catch (Exception e) {
    logger.error("Error reconstructing JWT: " + e.getMessage())
    response = new Response(Status.UNAUTHORIZED)
    response.headers.add("Content-Type", "application/json; charset=UTF-8")
    response.entity=new org.forgerock.json.JsonValue(["error": "Invalid JWT"])
    return response
}

return next.handle(context, request)