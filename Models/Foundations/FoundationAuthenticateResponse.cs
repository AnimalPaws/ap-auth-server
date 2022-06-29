using System.Text.Json.Serialization;

namespace ap_auth_server.Models.Foundations
{
    public class FoundationAuthenticateResponse
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public string? Email { get; set; }
        public string? Phone_Number { get; set; }
        public string? Department { get; set; }
        public string? City { get; set; }
        public string? Address { get; set; }
        public string? Role { get; set; }
        public bool IsVerified { get; set; }
        public bool Is_Blocked { get; set; }
        public bool Is_Restricted { get; set; }
        public DateTime? Created_At { get; set; }
        public DateTime? Updated_At { get; set; }
        public int Profile_Id { get; set; }
        public string? Token { get; set; }
    }
}
