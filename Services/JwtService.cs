using JWT;
using JWT.Serializers;
using JWT.Algorithms;
using JWT.Exceptions;

namespace ap_auth_server.Services
{
    public class JwtService
    {
        // Clave secreta que se asignará al token
        private readonly static string _secretKey = "JWTSecretKey";

        public static string Encode(Dictionary<string, object> payload)
        {
            IJsonSerializer serializer = new JsonNetSerializer();
            IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            
            var token = encoder.Encode(payload: payload, key: _secretKey);
            return token;
        }


    }
}
