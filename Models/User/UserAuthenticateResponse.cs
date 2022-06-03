using ap_auth_server.Entities.User;

namespace ap_auth_server.Models.Users
{
    public class UserAuthenticateResponse
    {
        public int? Id { get; set; }
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
        public bool? Phone_Number_Verified { get; set; }
        public bool? Email_Verified { get; set; }
        public bool? Is_Blocked { get; set; }
        public bool? Is_Restricted { get; set; }
        public DateTime? Created_At { get; set; }
        public DateTime? Updated_At { get; set; }
        //public int? Profile_Id { get; set; }

        //public virtual UserProfile Profile { get; set; }
        public string? Token { get; set; }
    }
}
