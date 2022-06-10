using ap_auth_server.Entities.User;
using System.Text.Json.Serialization;

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
        public string? Role { get; set; }
        public string? Phone_Number { get; set; }
        public DateTime Birthdate { get; set; }
        public string? Department { get; set; }
        public string? City { get; set; }
        public bool? Email_Verified { get; set; }
        public bool? Is_Blocked { get; set; }
        public bool? Is_Restricted { get; set; }
        public DateTime? Created_At { get; set; }
        public DateTime? Updated_At { get; set; }
        //public int? Profile_Id { get; set; }

        //public virtual UserProfile Profile { get; set; }
        public string? Token { get; set; }

        [JsonIgnore] // refresh token is returned in http only cookie
        public string RefreshToken { get; set; }

        /* public UserAuthenticateResponse(User user, string token)
        {
            Id = user.Id;
            First_Name = user.First_Name;
            Middle_Name = user.Middle_Name;
            Surname = user.Surname;
            Last_Name = user.Last_Name;
            Username = user.Username;
            Sex = user.Sex;
            Email = user.Email;
            Phone_Number = user.Phone_Number;
            Birthdate = user.Birthdate;
            Department = user.Department;
            City = user.City;
            Created_At = user.Created_At;
            Token = token;
        }*/
    }
}
