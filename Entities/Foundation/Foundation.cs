using System.Text.Json.Serialization;

namespace ap_auth_server.Entities.Foundation
{
    public class Foundation
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public string? Email { get; set; }
        [JsonIgnore]
        public string? Password { get; set; }
        public string? Phone_Number { get; set; }
        public string? Department { get; set; }
        public string? City { get; set; }
        public string? Address { get; set; }
        //public bool Email_Verified { get; set; }
        //public bool Is_Blocked { get; set; }
        //public bool Is_Restricted { get; set; }
        public DateTime Created_At { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; }

        public bool OwnsToken(string token)
        {
            return this.RefreshTokens?.Find(x => x.Token == token) != null;
        }
        //public DateTime Updated_At { get; set; }
        //public int? Profile_Id { get; set; }
        //public virtual FoundationProfile Profile { get; set; }

    }
}
