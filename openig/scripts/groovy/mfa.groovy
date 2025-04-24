import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.forgerock.json.jose.builders.JwtBuilderFactory
import org.forgerock.json.jose.jws.SignedJwt

def jwt=contexts["sts"]!=null?contexts["sts"].issuedToken:null

//logger.info("requiredModule: {}, timeoutSec: {}, location: {}", requiredModule, timeoutSec, location)

if (jwt == null || "".equalsIgnoreCase(jwt)) { 
    response = new Response(Status.UNAUTHORIZED)
    response.headers.add("Content-Type", "application/json; charset=UTF-8")
    response.entity=new org.forgerock.json.JsonValue(["error": "Missing JWT"])
    return response
}
try {
    String newLocation = location + URLEncoder.encode(contexts.router.originalUri.toString(), StandardCharsets.UTF_8);


    def claims = new JwtBuilderFactory().reconstruct(jwt, SignedJwt.class).getClaimsSet()
    def loginUrl = claims.getClaim("FullLoginURL")
    def authInstant = claims.getClaim("authInstant")

    logger.info("login url: {}, auth instant: {}", loginUrl, authInstant)

    def loginUrlFragment = "authIndexValue=totp"
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