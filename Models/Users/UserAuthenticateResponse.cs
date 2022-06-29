using System.Text.Json.Serialization;

namespace ap_auth_server.Models.Users
{
    public class UserAuthenticateResponse
    {
        /*public int? Id { get; set; }
        public string? First_Name { get; set; }
        public string? Middle_Name { get; set; }
        public string? Surname { get; set; }
        public string? Last_Name { get; set; }
        public string? Username { get; set; }
        public string? Sex { get; set; }
        public string? Email { get; set; }
        public string? Phone_Number { get; set; }
        public DateTime Birthdate { get; set; }
        public string? Department { get; set; }
        public string? City { get; set; }
        public string? Role { get; set; }
        public bool IsVerified { get; set; }
        public bool Is_Blocked { get; set; }
        public bool Is_Restricted { get; set; }
        public DateTime? Created_At { get; set; }
        public DateTime? Updated_At { get; set; }

        public int Profile_Id { get; set; }*/
        public string? Token { get; set; }
    }
}
